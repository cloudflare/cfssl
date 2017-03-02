package certadd

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

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/certdb/sql"
	"github.com/cloudflare/cfssl/certdb/testdb"
	"github.com/cloudflare/cfssl/ocsp"

	"encoding/base64"

	stdocsp "golang.org/x/crypto/ocsp"
)

func prepDB() (certdb.Accessor, error) {
	db := testdb.SQLiteDB("../../certdb/testdb/certstore_development.db")
	dbAccessor := sql.NewAccessor(db)

	return dbAccessor, nil
}

func makeRequest(t *testing.T, dbAccessor certdb.Accessor, signer ocsp.Signer, req map[string]interface{}) (resp *http.Response, body []byte) {
	ts := httptest.NewServer(NewHandler(dbAccessor, signer))
	defer ts.Close()

	blob, err := json.Marshal(req)
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

func makeCertificate() (serialNumber *big.Int, cert *x509.Certificate, pemBytes []byte, signer ocsp.Signer, err error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}

	serialNumberRange := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err = rand.Int(rand.Reader, serialNumberRange)
	if err != nil {
		return
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Cornell CS 5152"},
		},
		AuthorityKeyId: []byte{42, 42, 42, 42},
	}
	cert = &template

	issuerSerial, err := rand.Int(rand.Reader, serialNumberRange)
	if err != nil {
		return
	}
	responderSerial, err := rand.Int(rand.Reader, serialNumberRange)
	if err != nil {
		return
	}

	// Generate a CA certificate
	issuerTemplate := x509.Certificate{
		SerialNumber: issuerSerial,
		Subject: pkix.Name{
			Organization: []string{"Cornell CS 5152"},
		},
		AuthorityKeyId: []byte{42, 42, 42, 42},
		KeyUsage:       x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:           true,
		BasicConstraintsValid: true,
	}
	issuerBytes, err := x509.CreateCertificate(rand.Reader, &issuerTemplate, &issuerTemplate, &privKey.PublicKey, privKey)
	if err != nil {
		return
	}
	issuer, err := x509.ParseCertificate(issuerBytes)
	if err != nil {
		return
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
		return
	}
	responder, err := x509.ParseCertificate(responderBytes)
	if err != nil {
		return
	}

	signer, err = ocsp.NewSigner(issuer, responder, privKey, time.Hour)
	if err != nil {
		return
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, issuer, &privKey.PublicKey, privKey)

	if err != nil {
		return
	}

	pemBytes = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	return
}

func TestInsertValidCertificate(t *testing.T) {
	dbAccessor, err := prepDB()
	if err != nil {
		t.Fatal(err)
	}

	serialNumber, cert, pemBytes, signer, err := makeCertificate()

	if err != nil {
		t.Fatal(err)
	}

	resp, body := makeRequest(t, dbAccessor, signer, map[string]interface{}{
		"serial_number":            serialNumber.Text(16),
		"authority_key_identifier": hex.EncodeToString(cert.AuthorityKeyId),
		"status":                   "good",
		"pem":                      string(pemBytes),
	})

	if resp.StatusCode != http.StatusOK {
		t.Fatal("Expected HTTP OK, got", resp.StatusCode, string(body))
	}

	var response map[string]interface{}
	if err = json.Unmarshal(body, &response); err != nil {
		t.Fatal("Could not parse response: ", err)
	}
	responseResult := response["result"].(map[string]interface{})
	encodedOcsp := responseResult["ocsp_response"].(string)

	rawOcsp, err := base64.StdEncoding.DecodeString(encodedOcsp)
	if err != nil {
		t.Fatal("Could not base64 decode response: ", err)
	}
	returnedOcsp, err := stdocsp.ParseResponse(rawOcsp, nil)
	if err != nil {
		t.Fatal("Could not parse returned OCSP response", err)
	}

	ocsps, err := dbAccessor.GetOCSP(serialNumber.Text(16), hex.EncodeToString(cert.AuthorityKeyId))
	if err != nil {
		t.Fatal(err)
	}

	if len(ocsps) != 1 {
		t.Fatal("Expected 1 OCSP record to be inserted, but found ", len(ocsps))
	}

	parsedOcsp, err := stdocsp.ParseResponse([]byte(ocsps[0].Body), nil)
	if err != nil {
		t.Fatal(err)
	}

	if parsedOcsp.SerialNumber.Cmp(returnedOcsp.SerialNumber) != 0 {
		t.Fatal("The returned and inserted OCSP response have different serial numbers: got ", returnedOcsp.SerialNumber, " but decoded ", parsedOcsp.SerialNumber)
	}

	if parsedOcsp.SerialNumber.Cmp(serialNumber) != 0 {
		t.Fatal("Got the wrong serial number: expected", serialNumber, "but got", parsedOcsp.SerialNumber)
	}

	if parsedOcsp.Status != stdocsp.Good {
		t.Fatal("Expected OCSP response status to be ", stdocsp.Good,
			" but found ", parsedOcsp.Status)
	}
}

func TestInsertMissingSerial(t *testing.T) {
	dbAccessor, err := prepDB()
	if err != nil {
		t.Fatal(err)
	}

	_, cert, pemBytes, signer, err := makeCertificate()

	if err != nil {
		t.Fatal(err)
	}

	resp, body := makeRequest(t, dbAccessor, signer, map[string]interface{}{
		"authority_key_identifier": hex.EncodeToString(cert.AuthorityKeyId),
		"status":                   "good",
		"pem":                      string(pemBytes),
	})

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("Expected HTTP Bad Request", resp.StatusCode, string(body))
	}
}

func TestInsertMissingAKI(t *testing.T) {
	dbAccessor, err := prepDB()
	if err != nil {
		t.Fatal(err)
	}

	serialNumber, _, pemBytes, signer, err := makeCertificate()

	if err != nil {
		t.Fatal(err)
	}

	resp, body := makeRequest(t, dbAccessor, signer, map[string]interface{}{
		"serial_number": serialNumber.Text(16),
		"status":        "good",
		"pem":           string(pemBytes),
	})

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("Expected HTTP Bad Request", resp.StatusCode, string(body))
	}
}

func TestInsertMissingPEM(t *testing.T) {
	dbAccessor, err := prepDB()
	if err != nil {
		t.Fatal(err)
	}

	serialNumber, cert, _, signer, err := makeCertificate()

	if err != nil {
		t.Fatal(err)
	}

	resp, body := makeRequest(t, dbAccessor, signer, map[string]interface{}{
		"serial_number":            serialNumber.Text(16),
		"authority_key_identifier": hex.EncodeToString(cert.AuthorityKeyId),
		"status":                   "good",
	})

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("Expected HTTP Bad Request", resp.StatusCode, string(body))
	}
}

func TestInsertInvalidSerial(t *testing.T) {
	dbAccessor, err := prepDB()
	if err != nil {
		t.Fatal(err)
	}

	_, cert, pemBytes, signer, err := makeCertificate()

	if err != nil {
		t.Fatal(err)
	}

	resp, body := makeRequest(t, dbAccessor, signer, map[string]interface{}{
		"serial_number":            "this is not a serial number",
		"authority_key_identifier": hex.EncodeToString(cert.AuthorityKeyId),
		"status":                   "good",
		"pem":                      string(pemBytes),
	})

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("Expected HTTP Bad Request", resp.StatusCode, string(body))
	}
}

func TestInsertInvalidAKI(t *testing.T) {
	dbAccessor, err := prepDB()
	if err != nil {
		t.Fatal(err)
	}

	serialNumber, _, pemBytes, signer, err := makeCertificate()

	if err != nil {
		t.Fatal(err)
	}

	resp, body := makeRequest(t, dbAccessor, signer, map[string]interface{}{
		"serial_number":            serialNumber.Text(16),
		"authority_key_identifier": "this is not an AKI",
		"status":                   "good",
		"pem":                      string(pemBytes),
	})

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("Expected HTTP Bad Request, got", resp.StatusCode, string(body))
	}
}

func TestInsertInvalidStatus(t *testing.T) {
	dbAccessor, err := prepDB()
	if err != nil {
		t.Fatal(err)
	}

	serialNumber, cert, pemBytes, signer, err := makeCertificate()

	if err != nil {
		t.Fatal(err)
	}

	resp, body := makeRequest(t, dbAccessor, signer, map[string]interface{}{
		"serial_number":            serialNumber.Text(16),
		"authority_key_identifier": hex.EncodeToString(cert.AuthorityKeyId),
		"status":                   "invalid",
		"pem":                      string(pemBytes),
	})

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("Expected HTTP Bad Request", resp.StatusCode, string(body))
	}
}

func TestInsertInvalidPEM(t *testing.T) {
	dbAccessor, err := prepDB()
	if err != nil {
		t.Fatal(err)
	}

	serialNumber, cert, _, signer, err := makeCertificate()

	if err != nil {
		t.Fatal(err)
	}

	resp, body := makeRequest(t, dbAccessor, signer, map[string]interface{}{
		"serial_number":            serialNumber.Text(16),
		"authority_key_identifier": hex.EncodeToString(cert.AuthorityKeyId),
		"status":                   "good",
		"pem":                      "this is not a PEM certificate",
	})

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("Expected HTTP Bad Request, got", resp.StatusCode, string(body))
	}
}

func TestInsertWrongSerial(t *testing.T) {
	dbAccessor, err := prepDB()
	if err != nil {
		t.Fatal(err)
	}

	_, cert, pemBytes, signer, err := makeCertificate()

	if err != nil {
		t.Fatal(err)
	}

	resp, body := makeRequest(t, dbAccessor, signer, map[string]interface{}{
		"serial_number":            big.NewInt(1).Text(16),
		"authority_key_identifier": hex.EncodeToString(cert.AuthorityKeyId),
		"status":                   "good",
		"pem":                      string(pemBytes),
	})

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("Expected HTTP Bad Request", resp.StatusCode, string(body))
	}
}

func TestInsertWrongAKI(t *testing.T) {
	dbAccessor, err := prepDB()
	if err != nil {
		t.Fatal(err)
	}

	serialNumber, _, pemBytes, signer, err := makeCertificate()

	if err != nil {
		t.Fatal(err)
	}

	resp, body := makeRequest(t, dbAccessor, signer, map[string]interface{}{
		"serial_number":            serialNumber.Text(16),
		"authority_key_identifier": hex.EncodeToString([]byte{7, 7}),
		"status":                   "good",
		"pem":                      string(pemBytes),
	})

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("Expected HTTP Bad Request", resp.StatusCode, string(body))
	}
}

func TestInsertRevokedCertificate(t *testing.T) {
	dbAccessor, err := prepDB()
	if err != nil {
		t.Fatal(err)
	}

	serialNumber, cert, pemBytes, signer, err := makeCertificate()

	if err != nil {
		t.Fatal(err)
	}

	resp, body := makeRequest(t, dbAccessor, signer, map[string]interface{}{
		"serial_number":            serialNumber.Text(16),
		"authority_key_identifier": hex.EncodeToString(cert.AuthorityKeyId),
		"status":                   "revoked",
		"pem":                      string(pemBytes),
		"revoked_at":               time.Now(),
	})

	if resp.StatusCode != http.StatusOK {
		t.Fatal("Expected HTTP OK", resp.StatusCode, string(body))
	}

	ocsps, err := dbAccessor.GetOCSP(serialNumber.Text(16), hex.EncodeToString(cert.AuthorityKeyId))
	if err != nil {
		t.Fatal(err)
	}

	if len(ocsps) != 1 {
		t.Fatal("Expected 1 OCSP record to be inserted, but found ", len(ocsps))
	}

	response, err := stdocsp.ParseResponse([]byte(ocsps[0].Body), nil)
	if err != nil {
		t.Fatal(err)
	}

	if response.Status != stdocsp.Revoked {
		t.Fatal("Expected OCSP response status to be ", stdocsp.Revoked,
			" but found ", response.Status)
	}
}

func TestInsertRevokedCertificateWithoutTime(t *testing.T) {
	dbAccessor, err := prepDB()
	if err != nil {
		t.Fatal(err)
	}

	serialNumber, cert, pemBytes, signer, err := makeCertificate()

	if err != nil {
		t.Fatal(err)
	}

	resp, body := makeRequest(t, dbAccessor, signer, map[string]interface{}{
		"serial_number":            serialNumber.Text(16),
		"authority_key_identifier": hex.EncodeToString(cert.AuthorityKeyId),
		"status":                   "revoked",
		"pem":                      string(pemBytes),
		// Omit RevokedAt
	})

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("Expected HTTP Bad Request", resp.StatusCode, string(body))
	}

}
