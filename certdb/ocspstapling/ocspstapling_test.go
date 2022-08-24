package ocspstapling

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"os"
	"testing"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/certdb/sql"
	"github.com/cloudflare/cfssl/certdb/testdb"
	"github.com/cloudflare/cfssl/helpers"
	ct "github.com/google/certificate-transparency-go"
	"golang.org/x/crypto/ocsp"
)

func TestStapleSCTList(t *testing.T) {
	t.Skip("broken relating to https://github.com/cloudflare/cfssl/issues/1230")
	// issuer is a CA certificate.
	issuer, issuerPrivKey, err := makeCert(nil)
	if err != nil {
		t.Fatal(err)
	}

	// responderCert is a certificate for which to make an OCSP response.
	responderCert, _, err := makeCert(issuer)
	if err != nil {
		t.Fatal(err)
	}

	template := ocsp.Response{
		SerialNumber: responderCert.SerialNumber,
		IssuerHash:   crypto.SHA256,
		Status:       ocsp.Good,
	}

	// respDER is an OCSP response to be added to the database.
	respDER, err := ocsp.CreateResponse(issuer, responderCert, template, issuerPrivKey)
	if err != nil {
		t.Fatal(err)
	}

	// testDB is an empty DB of OCSP responses.
	pwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dbPath := pwd + "/../testdb/certstore_development.db"
	testDB := sql.NewAccessor(testdb.SQLiteDB(dbPath))

	// Next, we store the OCSP response in the DB.
	respSN := responderCert.SerialNumber.Text(16)
	testDB.InsertOCSP(certdb.OCSPRecord{
		Serial: respSN,
		Body:   base64.StdEncoding.EncodeToString(respDER),
		AKI:    "Cornell CS 5152",
	})

	var zeroSCT ct.SignedCertificateTimestamp
	err = StapleSCTList(testDB, respSN, "Cornell CS 5152", []ct.SignedCertificateTimestamp{zeroSCT},
		responderCert, issuer, issuerPrivKey)
	if err != nil {
		t.Fatal(err)
	}

	// Lastly, we verify that the SCT was inserted.
	recs, err := testDB.GetOCSP(respSN, "Cornell CS 5152")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) == 0 {
		t.Fatal("SCT could not be retrieved from DB:", zeroSCT)
	}

	respDER, err = base64.StdEncoding.DecodeString(recs[0].Body)
	if err != nil {
		t.Fatal(err)
	}

	response, err := ocsp.ParseResponse(respDER, issuer)
	if err != nil {
		t.Fatal(err)
	}

	scts, err := helpers.SCTListFromOCSPResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	if len(scts) == 0 {
		t.Fatal("No SCTs in OCSP response:", response)
	}

	// Here, we check the equivalence of the SCT we inserted with the SCT
	// returned by SCTListFromOCSPResponse.

	// sctEquals returns true if all fields of both SCTs are equivalent.
	sctEquals := func(sctA, sctB ct.SignedCertificateTimestamp) bool {
		if sctA.SCTVersion == sctB.SCTVersion &&
			sctA.LogID == sctB.LogID &&
			sctA.Timestamp == sctB.Timestamp &&
			bytes.Equal(sctA.Extensions, sctB.Extensions) &&
			sctA.Signature.Algorithm == sctB.Signature.Algorithm &&
			bytes.Equal(sctA.Signature.Signature, sctA.Signature.Signature) {
			return true
		}
		return false
	}

	if !sctEquals(scts[0], zeroSCT) {
		t.Fatal("SCTs do not match:", "\nGot --", scts[0], "\nExpected --", zeroSCT)
	}
}

// serialCounter stores the next serial number to be issued by nextSN.
var serialCounter int64

// nextSN returns a new big.Int for creating x509 certificates.
func nextSN() *big.Int {
	i := big.NewInt(serialCounter)
	serialCounter++
	return i
}

// makeCert returns a new x509 certificate with the given issuer certificate.
// If issuer is nil, the certificate is self-signed.
func makeCert(issuer *x509.Certificate) (*x509.Certificate, crypto.Signer, error) {
	// Create a new private key
	privKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: nextSN(),
		Subject: pkix.Name{
			Organization: []string{"Cornell CS 5152"},
		},
		AuthorityKeyId: []byte{42, 42, 42, 42},
	}

	if issuer == nil { // the cert is self-signed
		issuer = &template
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, issuer, privKey.Public(), privKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}

	return cert, privKey, nil
}
