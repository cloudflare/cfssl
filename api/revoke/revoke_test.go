package revoke

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/certdb/testdb"
)

func prepDB() (db *sql.DB, err error) {
	db = testdb.SQLiteDB("../../certdb/testdb/certstore_development.db")
	expirationTime := time.Now().AddDate(1, 0, 0)
	var cert = &certdb.CertificateRecord{
		Serial: "1",
		Expiry: expirationTime,
		PEM:    "unexpired cert",
	}

	err = certdb.InsertCertificate(db, cert)
	if err != nil {
		return nil, err
	}

	return
}

func testRevokeCert(t *testing.T, db *sql.DB, serial string, reason string) (resp *http.Response, body []byte) {
	ts := httptest.NewServer(NewHandler(db))
	defer ts.Close()

	obj := map[string]interface{}{}

	obj["serial"] = serial

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
	db, err := prepDB()
	if err != nil {
		t.Fatal(err)
	}

	resp, _ := testRevokeCert(t, db, "", "")

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("expected bad request response")
	}
}

func TestRevocation(t *testing.T) {
	db, err := prepDB()
	if err != nil {
		t.Fatal(err)
	}

	resp, body := testRevokeCert(t, db, "1", "5")

	if resp.StatusCode != http.StatusOK {
		t.Fatal("unexpected HTTP status code; expected OK", string(body))
	}
	message := new(api.Response)
	err = json.Unmarshal(body, message)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	cert, err := certdb.GetCertificate(db, "1")
	if err != nil {
		t.Fatal("failed to get certificate ", err)
	}

	if cert.Status != "revoked" || cert.Reason != 5 {
		t.Fatal("cert was not correctly revoked")
	}
}
