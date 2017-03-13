package ocspstapling

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/certdb/sql"
	"github.com/cloudflare/cfssl/certdb/testdb"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/google/certificate-transparency/go"
	"golang.org/x/crypto/ocsp"
	"math/big"
	"os"
	"testing"
)

func TestStapleSCTList(t *testing.T) {
	// Create a CA certificate
	issuer, issuerPrivKey, err := makeCert(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create a certificate for which to make an OCSP response
	responderCert, _, err := makeCert(issuer)
	if err != nil {
		t.Fatal(err)
	}

	// Create an OCSP response
	template := ocsp.Response{ // TODO: populate
		SerialNumber: responderCert.SerialNumber,
		IssuerHash:   crypto.SHA256,
		Status:       ocsp.Good,
	}

	respDER, err := ocsp.CreateResponse(issuer, responderCert, template, issuerPrivKey)
	if err != nil {
		t.Fatal(err)
	}

	// Create an empty DB of OCSP responses
	// TODO: Test non-sqlite db's
	gopath := os.Getenv("GOPATH")
	dbPath := gopath + "/src/github.com/cloudflare/cfssl/certdb/testdb/certstore_development.db"
	testDB := sql.NewAccessor(testdb.SQLiteDB(dbPath))

	// Store the OCSP response in the DB
	respSN := responderCert.SerialNumber.Text(16)
	testDB.InsertOCSP(certdb.OCSPRecord{
		Serial: respSN,
		Body:   base64.StdEncoding.EncodeToString(respDER),
		//Expiry:,
	})

	// Insert an SCT for the OCSP response we created
	var zeroSCT ct.SignedCertificateTimestamp
	err = StapleSCTList(testDB, respSN, "", []ct.SignedCertificateTimestamp{zeroSCT}, issuer, issuerPrivKey)
	if err != nil {
		t.Fatal(err)
	}

	// Verify that the SCT was inserted
	recs, err := testDB.GetOCSP(respSN, "")
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

	scts := SCTListFromOCSPResponse(response)
	if len(scts) == 0 {
		t.Fatal("No SCTs in OCSP response:", response)
	}

	// TODO: Verify that scts[0] is equivalent to zeroSCT
}

// TODO: COMMENT
var serialCounter int64

// TODO: COMMENT
func nextSN() *big.Int {
	i := big.NewInt(serialCounter)
	serialCounter++
	return i
}

// TODO: COMMENT
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

// SCTListFromOCSPResponse extracts the SCTList from an ocsp.Response
// Returns an empty list if the SCT extension was not found or could not be
// unmarshalled.
// TODO: Move to helpers?
func SCTListFromOCSPResponse(response *ocsp.Response) []ct.SignedCertificateTimestamp {
	// Find the SCTListExtension in the ocsp response
	var SCTListExtension, ext pkix.Extension
	for _, ext = range response.Extensions {
		if ext.Id.Equal(sctExtOid) {
			SCTListExtension = ext
			break
		}
	}

	// Extract the sctList from the extension
	var sctList []ct.SignedCertificateTimestamp
	if SCTListExtension.Value != nil {
		// Extract the SCTList
		var serializedSCTList []byte
		rest := SCTListExtension.Value
		// TODO: Is it correct to pass in the same slice to
		// multiple calls of Unmarshal?
		for len(rest) != 0 {
			var err error
			rest, err = asn1.Unmarshal(rest, &serializedSCTList)
			if err != nil {
				// { unmarshaling error }
				return nil
			}
		}
		desList, err := helpers.DeserializeSCTList(serializedSCTList)
		if err != nil {
			// { deserializing error }
			return nil
		}
		sctList = desList
	}
	return sctList
}
