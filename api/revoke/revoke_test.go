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

	"bitbucket.org/liamstask/goose/lib/goose"
	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/certdb"
)

// Largely duplicates the functionality of prepDB in certdb_test
func prepDB() (db *sql.DB, err error) {
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		return nil, err
	}

	var dbconf *goose.DBConf
	dbconf, err = goose.NewDBConf("../../certdb/sqlite/", "test", "")
	if err != nil {
		return nil, err
	}

	err = goose.RunMigrationsOnDb(dbconf, "../../certdb/sqlite/", 1, db)
	if err != nil {
		return nil, err
	}

	expirationTime := time.Now().AddDate(1, 0, 0)
	var cert = &certdb.CertificateRecord{
		Serial:    "1",
		CALabel:   "",
		Status:    "",
		Reason:    0,
		ExpiresAt: &expirationTime,
		RevokedAt: nil,
		PEM:       "unexpired cert",
	}

	err = certdb.InsertCertificate(db, cert)
	if err != nil {
		return nil, err
	}

	return
}

func testRevokeCert(t *testing.T, db *sql.DB, serial string, reason *string) (resp *http.Response, body []byte) {
	ts := httptest.NewServer(NewHandler(db))
	defer ts.Close()

	obj := map[string]interface{}{}

	obj["serial"] = serial

	if reason != nil {
		obj["reason"] = *reason
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

	resp, _ := testRevokeCert(t, db, "", nil)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("expected bad request response")
	}
}

func TestRevocation(t *testing.T) {
	db, err := prepDB()
	if err != nil {
		t.Fatal(err)
	}

	reason := "5"
	resp, body := testRevokeCert(t, db, "1", &reason)

	if resp.StatusCode != http.StatusOK {
		t.Fatal("unexpected HTTP status code; expected OK", string(body))
	}
	message := new(api.Response)
	err = json.Unmarshal(body, message)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	var cert *certdb.CertificateRecord
	cert, err = certdb.GetCertificateRecord(db, "1")
	if err != nil {
		t.Fatal(err)
	}

	if cert.Status != "revoked" || cert.Reason != 5 || cert.RevokedAt == nil {
		t.Fatal("cert was not correctly revoked")
	}
}
