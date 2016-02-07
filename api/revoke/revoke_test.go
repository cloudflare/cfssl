package revoke

import (
	"bytes"
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
)

func prepDB() (certdb.Accessor, error) {
	db := testdb.SQLiteDB("../../certdb/testdb/certstore_development.db")
	expirationTime := time.Now().AddDate(1, 0, 0)
	var cert = &certdb.CertificateRecord{
		Serial: "1",
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

func testRevokeCert(t *testing.T, dbAccessor certdb.Accessor, serial string, reason string) (resp *http.Response, body []byte) {
	ts := httptest.NewServer(NewHandler(dbAccessor))
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
	dbAccessor, err := prepDB()
	if err != nil {
		t.Fatal(err)
	}

	resp, _ := testRevokeCert(t, dbAccessor, "", "")

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("expected bad request response")
	}
}

func TestRevocation(t *testing.T) {
	dbAccessor, err := prepDB()
	if err != nil {
		t.Fatal(err)
	}

	resp, body := testRevokeCert(t, dbAccessor, "1", "5")

	if resp.StatusCode != http.StatusOK {
		t.Fatal("unexpected HTTP status code; expected OK", string(body))
	}
	message := new(api.Response)
	err = json.Unmarshal(body, message)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	cert, err := dbAccessor.GetCertificate("1")
	if err != nil {
		t.Fatal("failed to get certificate ", err)
	}

	if cert.Status != "revoked" || cert.Reason != 5 {
		t.Fatal("cert was not correctly revoked")
	}
}
