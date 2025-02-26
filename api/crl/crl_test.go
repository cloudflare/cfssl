package crl

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/certdb/sql"
	"github.com/cloudflare/cfssl/certdb/testdb"
	"github.com/cloudflare/cfssl/helpers"
)

const (
	fakeAKI       = "fake aki"
	testCaFile    = "../testdata/ca.pem"
	testCaKeyFile = "../testdata/ca_key.pem"
)

func prepDB() (certdb.Accessor, error) {
	db := testdb.SQLiteDB("../../certdb/testdb/certstore_development.db")
	expirationTime := time.Now().AddDate(1, 0, 0)
	var cert = certdb.CertificateRecord{
		Serial:    "1",
		AKI:       fakeAKI,
		Expiry:    expirationTime,
		PEM:       "revoked cert",
		Status:    "revoked",
		RevokedAt: time.Now(),
		Reason:    4,
	}

	dbAccessor := sql.NewAccessor(db)
	err := dbAccessor.InsertCertificate(cert)
	if err != nil {
		return nil, err
	}

	return dbAccessor, nil
}

func testGetCRL(t *testing.T, dbAccessor certdb.Accessor, expiry, number string) (resp *http.Response, body []byte) {
	handler, err := NewHandler(dbAccessor, testCaFile, testCaKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(handler)
	defer ts.Close()

	query := url.Values{}
	if expiry != "" {
		query.Set("expiry", expiry)
	}
	if number != "" {
		query.Set("crl-number", number)
	}

	resp, err = http.Get(ts.URL + "?" + query.Encode())
	if err != nil {
		t.Fatal(err)
	}
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestCRLGeneration(t *testing.T) {
	dbAccessor, err := prepDB()
	if err != nil {
		t.Fatal(err)
	}

	resp, body := testGetCRL(t, dbAccessor, "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatal("unexpected HTTP status code; expected OK", string(body))
	}
	message := new(api.Response)
	err = json.Unmarshal(body, message)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	crlBytes := message.Result.(string)
	crlBytesDER, err := base64.StdEncoding.DecodeString(crlBytes)
	if err != nil {
		t.Fatal("failed to decode certificate ", err)
	}
	parsedCrl, err := x509.ParseRevocationList(crlBytesDER)
	if err != nil {
		t.Fatal("failed to get certificate ", err)
	}
	if parsedCrl.NextUpdate.Before(time.Now().Add(5 * helpers.OneDay)) {
		t.Fatal("the request will expire after 5 days, this shouldn't happen")
	}
	certs := parsedCrl.RevokedCertificateEntries
	if len(certs) != 1 {
		t.Fatal("failed to get one certificate")
	}

	cert := certs[0]

	if cert.SerialNumber.String() != "1" {
		t.Fatal("cert was not correctly inserted in CRL, serial was ", cert.SerialNumber)
	}

	if big.NewInt(0).Cmp(parsedCrl.Number) != 0 {
		t.Fatalf("CRL number was incorrect: %s, expect: 0", parsedCrl.Number)
	}
}

func TestCRLGenerationWithExpiry(t *testing.T) {
	dbAccessor, err := prepDB()
	if err != nil {
		t.Fatal(err)
	}

	resp, body := testGetCRL(t, dbAccessor, "119h", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatal("unexpected HTTP status code; expected OK", string(body))
	}
	message := new(api.Response)
	err = json.Unmarshal(body, message)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	crlBytes := message.Result.(string)
	crlBytesDER, err := base64.StdEncoding.DecodeString(crlBytes)
	if err != nil {
		t.Fatal("failed to decode certificate ", err)
	}
	parsedCrl, err := x509.ParseRevocationList(crlBytesDER)
	if err != nil {
		t.Fatal("failed to get certificate ", err)
	}
	if !parsedCrl.NextUpdate.Before(time.Now().Add(5 * helpers.OneDay)) {
		t.Fatal("the request should have expired")
	}
	certs := parsedCrl.RevokedCertificateEntries
	if len(certs) != 1 {
		t.Fatal("failed to get one certificate")
	}

	cert := certs[0]

	if cert.SerialNumber.String() != "1" {
		t.Fatal("cert was not correctly inserted in CRL, serial was ", cert.SerialNumber)
	}

	if big.NewInt(0).Cmp(parsedCrl.Number) != 0 {
		t.Fatalf("CRL number was incorrect: %s, expect: 0", parsedCrl.Number)
	}
}

func TestCRLGenerationWithNumber(t *testing.T) {
	dbAccessor, err := prepDB()
	if err != nil {
		t.Fatal(err)
	}

	resp, body := testGetCRL(t, dbAccessor, "", "1")
	if resp.StatusCode != http.StatusOK {
		t.Fatal("unexpected HTTP status code; expected OK", string(body))
	}
	message := new(api.Response)
	err = json.Unmarshal(body, message)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	crlBytes := message.Result.(string)
	crlBytesDER, err := base64.StdEncoding.DecodeString(crlBytes)
	if err != nil {
		t.Fatal("failed to decode certificate ", err)
	}
	parsedCrl, err := x509.ParseRevocationList(crlBytesDER)
	if err != nil {
		t.Fatal("failed to get certificate ", err)
	}
	certs := parsedCrl.RevokedCertificateEntries
	if len(certs) != 1 {
		t.Fatal("failed to get one certificate")
	}

	cert := certs[0]

	if cert.SerialNumber.String() != "1" {
		t.Fatal("cert was not correctly inserted in CRL, serial was ", cert.SerialNumber)
	}

	if big.NewInt(1).Cmp(parsedCrl.Number) != 0 {
		t.Fatalf("CRL number was incorrect: %s, expect: 1", parsedCrl.Number)
	}
}
