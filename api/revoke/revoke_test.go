package revoke

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/certdb/sql"
	"github.com/cloudflare/cfssl/certdb/testdb"
	"github.com/cloudflare/cfssl/ocsp"

	stdocsp "golang.org/x/crypto/ocsp"
)

const (
	fakeAKI = "fake aki"
)

func prepDB() (certdb.Accessor, error) {
	db := testdb.SQLiteDB("../../certdb/testdb/certstore_development.db")
	expirationTime := time.Now().AddDate(1, 0, 0)
	var cert = certdb.CertificateRecord{
		Serial: "1",
		AKI:    fakeAKI,
		Expiry: expirationTime,
		PEM:    "unexpired cert",
	}

	dbAccessor := sql.NewAccessor(db)
	err := dbAccessor.InsertCertificate(cert)
	if err != nil {
		return nil, err
	}

	return dbAccessor, nil
}

func testRevokeCert(t *testing.T, dbAccessor certdb.Accessor, serial, aki, reason string) (resp *http.Response, body []byte) {
	ts := httptest.NewServer(NewHandler(dbAccessor))
	defer ts.Close()

	obj := map[string]interface{}{}

	obj["serial"] = serial
	obj["authority_key_id"] = aki

	if reason != "" {
		obj["reason"] = reason
	}

	blob, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}

	resp, err = http.Post(ts.URL, "application/json", bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestInvalidRevocation(t *testing.T) {
	dbAccessor, err := prepDB()
	if err != nil {
		t.Fatal(err)
	}

	resp, _ := testRevokeCert(t, dbAccessor, "", "", "")

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("expected bad request response")
	}
}

func TestRevocation(t *testing.T) {
	dbAccessor, err := prepDB()
	if err != nil {
		t.Fatal(err)
	}

	resp, body := testRevokeCert(t, dbAccessor, "1", fakeAKI, "5")

	if resp.StatusCode != http.StatusOK {
		t.Fatal("unexpected HTTP status code; expected OK", string(body))
	}
	message := new(api.Response)
	err = json.Unmarshal(body, message)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	certs, err := dbAccessor.GetCertificate("1", fakeAKI)
	if err != nil {
		t.Fatal("failed to get certificate ", err)
	}
	if len(certs) != 1 {
		t.Fatal("failed to get one certificate")
	}

	cert := certs[0]

	if cert.Status != "revoked" || cert.Reason != 5 {
		t.Fatal("cert was not correctly revoked")
	}
}

// TestOCSPGeneration tests that revoking a certificate (when the
// request handler has an OCSP response signer) generates an
// appropriate OCSP response in the certdb.
func TestOCSPGeneration(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serialNumberRange := new(big.Int).Lsh(big.NewInt(1), 128)

	// 1. Generate a CA certificate to serve as the signing certificate.
	issuerSerial, err := rand.Int(rand.Reader, serialNumberRange)
	if err != nil {
		t.Fatal(err)
	}
	issuerTemplate := x509.Certificate{
		SerialNumber: issuerSerial,
		Subject: pkix.Name{
			Organization: []string{"cfssl unit test"},
		},
		AuthorityKeyId: []byte{42, 42, 42, 42},
		KeyUsage:       x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:           true,
		BasicConstraintsValid: true,
	}
	issuerBytes, err := x509.CreateCertificate(rand.Reader, &issuerTemplate, &issuerTemplate, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerBytes)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Generate a certificate signed by the CA certificate to revoke.
	revokedSerial, err := rand.Int(rand.Reader, serialNumberRange)
	if err != nil {
		t.Fatal(err)
	}
	revokedTemplate := x509.Certificate{
		SerialNumber: revokedSerial,
		Subject: pkix.Name{
			Organization: []string{"Cornell CS 5152"},
		},
		AuthorityKeyId: []byte{42, 42, 42, 42},
	}
	revokedBytes, err := x509.CreateCertificate(rand.Reader, &revokedTemplate, issuer, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatal(err)
	}

	revoked := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: revokedBytes,
	})

	revokedAKI := hex.EncodeToString(revokedTemplate.AuthorityKeyId)
	revokedSerialStr := revokedSerial.Text(16)

	// 3. Generate a certificate to use as the responder certificate.
	responderSerial, err := rand.Int(rand.Reader, serialNumberRange)
	if err != nil {
		t.Fatal(err)
	}
	responderTemplate := x509.Certificate{
		SerialNumber: responderSerial,
		Subject: pkix.Name{
			Organization: []string{"Cornell CS 5152 Responder"},
		},
		AuthorityKeyId: []byte{42, 42, 42, 43},
	}
	responderBytes, err := x509.CreateCertificate(rand.Reader, &responderTemplate, &responderTemplate, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := x509.ParseCertificate(responderBytes)
	if err != nil {
		t.Fatal(err)
	}

	// 4. Create the OCSP signer
	signer, err := ocsp.NewSigner(issuer, responder, privKey, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// 5. Spin up the test server
	// 5a. Prepare the DB
	dbAccessor, err := prepDB()
	if err != nil {
		t.Fatal(err)
	}
	expirationTime := time.Now().AddDate(1, 0, 0)
	cr := certdb.CertificateRecord{
		Serial: revokedSerialStr,
		AKI:    revokedAKI,
		Expiry: expirationTime,
		PEM:    string(revoked),
	}
	if err := dbAccessor.InsertCertificate(cr); err != nil {
		t.Fatal(err)
	}

	// 5b. Start the test server
	ts := httptest.NewServer(NewOCSPHandler(dbAccessor, signer))
	defer ts.Close()

	// 6. Prepare the revocation request
	obj := map[string]interface{}{}

	obj["serial"] = revokedSerialStr
	obj["authority_key_id"] = revokedAKI
	obj["reason"] = "unspecified"

	blob, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}

	// Get the original number of OCSP responses
	ocspsBefore, _ := dbAccessor.GetOCSP(revokedSerialStr, revokedAKI)
	ocspCountBefore := len(ocspsBefore)

	// 7. Send the revocation request
	resp, err := http.Post(ts.URL, "application/json", bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatal("unexpected HTTP status code; expected OK", string(body))
	}
	message := new(api.Response)
	err = json.Unmarshal(body, message)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	// 8. Make sure the certificate record was updated
	certs, err := dbAccessor.GetCertificate(revokedSerialStr, revokedAKI)
	if err != nil {
		t.Fatal("failed to get certificate ", err)
	}
	if len(certs) != 1 {
		t.Fatal("failed to get one certificate")
	}

	cert := certs[0]

	if cert.Status != "revoked" || cert.Reason != stdocsp.Unspecified {
		t.Fatal("cert was not correctly revoked")
	}

	// 9. Make sure there is an OCSP record
	ocsps, err := dbAccessor.GetOCSP(revokedSerialStr, revokedAKI)
	if err != nil {
		t.Fatal("failed to get OCSP responses ", err)
	}

	if len(ocsps) == 0 {
		t.Fatal("No OCSP response generated")
	}

	if len(ocsps) <= ocspCountBefore {
		t.Fatal("No new OCSP response found")
	}
}
