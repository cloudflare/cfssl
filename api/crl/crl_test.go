package crl

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
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

func testGetCRL(t *testing.T, dbAccessor certdb.Accessor, expiry string) (resp *http.Response, body []byte) {
	handler, err := NewHandler(dbAccessor, testCaFile, testCaKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(handler)
	defer ts.Close()

	if expiry != "" {
		resp, err = http.Get(ts.URL + "?expiry=" + expiry)
	} else {
		resp, err = http.Get(ts.URL)
	}
	if err != nil {
		t.Fatal(err)
	}
	body, err = ioutil.ReadAll(resp.Body)
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

	resp, body := testGetCRL(t, dbAccessor, "")
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
	parsedCrl, err := x509.ParseCRL(crlBytesDER)
	if err != nil {
		t.Fatal("failed to get certificate ", err)
	}
	if parsedCrl.HasExpired(time.Now().Add(5 * helpers.OneDay)) {
		t.Fatal("the request will expire after 5 days, this shouldn't happen")
	}
	certs := parsedCrl.TBSCertList.RevokedCertificates
	if len(certs) != 1 {
		t.Fatal("failed to get one certificate")
	}

	cert := certs[0]

	if cert.SerialNumber.String() != "1" {
		t.Fatal("cert was not correctly inserted in CRL, serial was ", cert.SerialNumber)
	}
}

func TestCRLGenerationWithExpiry(t *testing.T) {
	dbAccessor, err := prepDB()
	if err != nil {
		t.Fatal(err)
	}

	resp, body := testGetCRL(t, dbAccessor, "119h")
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
	parsedCrl, err := x509.ParseCRL(crlBytesDER)
	if err != nil {
		t.Fatal("failed to get certificate ", err)
	}
	if !parsedCrl.HasExpired(time.Now().Add(5 * helpers.OneDay)) {
		t.Fatal("the request should have expired")
	}
	certs := parsedCrl.TBSCertList.RevokedCertificates
	if len(certs) != 1 {
		t.Fatal("failed to get one certificate")
	}

	cert := certs[0]

	if cert.SerialNumber.String() != "1" {
		t.Fatal("cert was not correctly inserted in CRL, serial was ", cert.SerialNumber)
	}
}
