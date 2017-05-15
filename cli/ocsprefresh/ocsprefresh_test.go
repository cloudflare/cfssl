package ocsprefresh

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"testing"
	"time"

	"io/ioutil"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/certdb/sql"
	"github.com/cloudflare/cfssl/certdb/testdb"
	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/google/certificate-transparency/go"
	"github.com/google/certificate-transparency/go/tls"
	"golang.org/x/crypto/ocsp"
)

var dbAccessor certdb.Accessor

func TestOCSPRefreshMain(t *testing.T) {
	db := testdb.SQLiteDB("../../certdb/testdb/certstore_development.db")

	certPEM, err := ioutil.ReadFile("../../ocsp/testdata/cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}

	expirationTime := time.Now().AddDate(1, 0, 0)
	certRecord := certdb.CertificateRecord{
		Serial: cert.SerialNumber.String(),
		AKI:    hex.EncodeToString(cert.AuthorityKeyId),
		Expiry: expirationTime,
		PEM:    string(certPEM),
		Status: "good",
	}

	dbAccessor = sql.NewAccessor(db)
	err = dbAccessor.InsertCertificate(certRecord)
	if err != nil {
		t.Fatal(err)
	}

	testOCSPRefresh(t, cert)
	testSCTStapling(t, cert)
	testRevokeCertAndGetUnexpiredOCSPs(t, certRecord)
}

func testOCSPRefresh(t *testing.T, cert *x509.Certificate) {
	err := ocsprefreshMain([]string{}, cli.Config{
		CAFile:           "../../ocsp/testdata/ca.pem",
		ResponderFile:    "../../ocsp/testdata/server.crt",
		ResponderKeyFile: "../../ocsp/testdata/server.key",
		DBConfigFile:     "../testdata/db-config.json",
		Interval:         helpers.OneDay,
	})

	if err != nil {
		t.Fatal(err)
	}

	records, err := dbAccessor.GetUnexpiredOCSPs()
	if err != nil {
		t.Fatal("Failed to get OCSP responses")
	}

	if len(records) != 1 {
		t.Fatal("Expected one OCSP response")
	}

	var resp *ocsp.Response
	resp, err = ocsp.ParseResponse([]byte(records[0].Body), nil)
	if err != nil {
		t.Fatal("Failed to parse OCSP response")
	}
	if resp.Status != ocsp.Good {
		t.Fatal("Expected cert status 'good'")
	}
}

// testSCTStapling verifies that the OCSP response for the given certificate
// contains the corresponding SCT.
func testSCTStapling(t *testing.T, cert *x509.Certificate) {
	// Insert an SCT corresponding to the certificate
	var logIDSHA ct.SHA256Hash
	logID := "pLkJkLQYWBSHuxOizGdwCjw1mAT5G9+443fNDsgN3BA="
	shaID, err := base64.StdEncoding.DecodeString(logID)
	copy(logIDSHA[:], shaID)
	if err != nil {
		t.Fatal("Failed to generate CT log ID")
	}
	sct := ct.SignedCertificateTimestamp{
		LogID:      logIDSHA,
		Timestamp:  ^uint64(0),
		SCTVersion: 0,
		Signature: ct.DigitallySigned(tls.DigitallySigned{
			Signature: []byte{0x1, 0x2, 0x3, 0x4, 0x5},
			Algorithm: tls.SignatureAndHashAlgorithm{
				Hash:      tls.SHA256,
				Signature: tls.RSA,
			},
		}),
		Extensions: []byte{0xa, 0xb, 0xc, 0xd, 0xe},
	}
	serializedSCT, err := ct.SerializeSCT(sct)
	if err != nil {
		t.Fatal("Failed to serialize SCT:", err)
	}
	sctRecord := certdb.SCTRecord{
		Serial:    cert.SerialNumber.String(),
		AKI:       hex.EncodeToString(cert.AuthorityKeyId),
		LogID:     logID,
		Timestamp: strconv.FormatUint(sct.Timestamp, 10),
		Body:      hex.EncodeToString(serializedSCT),
	}
	dbAccessor.InsertSCT(sctRecord)

	err = ocsprefreshMain([]string{}, cli.Config{
		CAFile:           "../../ocsp/testdata/ca.pem",
		ResponderFile:    "../../ocsp/testdata/server.crt",
		ResponderKeyFile: "../../ocsp/testdata/server.key",
		DBConfigFile:     "../testdata/db-config.json",
		Interval:         helpers.OneDay,
	})

	if err != nil {
		t.Fatal(err)
	}

	// Check that the generated OCSP response has the stapled SCT
	records, err := dbAccessor.GetUnexpiredOCSPs()
	if err != nil {
		t.Fatal("Failed to get OCSP responses")
	}

	if len(records) != 1 {
		t.Fatal("Expected one OCSP response")
	}

	var resp *ocsp.Response
	resp, err = ocsp.ParseResponse([]byte(records[0].Body), nil)
	if err != nil {
		t.Fatal("Failed to parse OCSP response")
	}
	if resp.Status != ocsp.Good {
		t.Fatal("Expected cert status 'good'")
	}

	sctsFromResp, err := helpers.SCTListFromOCSPResponse(resp)
	if err != nil {
		t.Fatal("Failed to extract stapled SCT:", err)
	}

	if len(sctsFromResp) != 1 {
		t.Fatal("Expected one SCT")
	}

	if respSCT := sctsFromResp[0]; !bytes.Equal(sct.LogID[:], respSCT.LogID[:]) ||
		sct.SCTVersion != respSCT.SCTVersion || sct.Timestamp != respSCT.Timestamp ||
		!bytes.Equal(sct.Signature.Signature, respSCT.Signature.Signature) ||
		sct.Signature.Algorithm != respSCT.Signature.Algorithm ||
		!bytes.Equal(sct.Extensions, respSCT.Extensions) {
		t.Fatal("SCTs don't match:", sct, "--", respSCT)
	}
}

func testRevokeCertAndGetUnexpiredOCSPs(t *testing.T, certRecord certdb.CertificateRecord) {
	err := dbAccessor.RevokeCertificate(certRecord.Serial, certRecord.AKI, ocsp.KeyCompromise)
	if err != nil {
		t.Fatal("Failed to revoke certificate")
	}

	err = ocsprefreshMain([]string{}, cli.Config{
		CAFile:           "../../ocsp/testdata/ca.pem",
		ResponderFile:    "../../ocsp/testdata/server.crt",
		ResponderKeyFile: "../../ocsp/testdata/server.key",
		DBConfigFile:     "../testdata/db-config.json",
		Interval:         helpers.OneDay,
	})

	if err != nil {
		t.Fatal(err)
	}

	records, err := dbAccessor.GetUnexpiredOCSPs()
	if err != nil {
		t.Fatal("Failed to get OCSP responses")
	}

	if len(records) != 1 {
		t.Fatal("Expected one OCSP response")
	}

	resp, err := ocsp.ParseResponse([]byte(records[0].Body), nil)
	if err != nil {
		t.Fatal("Failed to parse OCSP response")
	}
	if resp.Status != ocsp.Revoked {
		t.Fatal("Expected cert status 'revoked'")
	}
}
