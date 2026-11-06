package signhandler

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"

	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/certdb/sql"
	"github.com/cloudflare/cfssl/certdb/testdb"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/info"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
)

const (
	testCaFile    = "../testdata/ca.pem"
	testCaKeyFile = "../testdata/ca_key.pem"
	testCSRFile   = "../testdata/csr.pem"
)

// GetUnexpiredCertificates sometimes doesn't return a certificate with an
// expiry of 1m as above
var validLocalConfigLongerExpiry = `
{
	"signing": {
		"default": {
		    "usages": ["digital signature", "email protection"],
			"expiry": "10m"
		}
	}
}`

var dbAccessor certdb.Accessor

func TestSignerDBPersistence(t *testing.T) {
	conf, err := config.LoadConfig([]byte(validLocalConfigLongerExpiry))
	if err != nil {
		t.Fatal(err)
	}

	var s *local.Signer
	s, err = local.NewSignerFromFile(testCaFile, testCaKeyFile, conf.Signing)
	if err != nil {
		t.Fatal(err)
	}

	db := testdb.SQLiteDB("../../certdb/testdb/certstore_development.db")
	if err != nil {
		t.Fatal(err)
	}

	dbAccessor = sql.NewAccessor(db)
	s.SetDBAccessor(dbAccessor)

	var handler *api.HTTPHandler
	handler, err = NewHandlerFromSigner(signer.Signer(s))
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(handler)
	defer ts.Close()

	var csrPEM, body []byte
	csrPEM, err = os.ReadFile(testCSRFile)
	if err != nil {
		t.Fatal(err)
	}

	blob, err := json.Marshal(&map[string]string{"certificate_request": string(csrPEM)})
	if err != nil {
		t.Fatal(err)
	}

	var resp *http.Response
	resp, err = http.Post(ts.URL, "application/json", bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatal(resp.Status, string(body))
	}

	message := new(api.Response)
	err = json.Unmarshal(body, message)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	if !message.Success {
		t.Fatal("API operation failed")
	}

	crs, err := dbAccessor.GetUnexpiredCertificates()
	if err != nil {
		t.Fatal("Failed to get unexpired certificates")
	}

	if len(crs) != 1 {
		t.Fatal("Expected 1 unexpired certificate in the database after signing 1: len(crs)=", len(crs))
	}
}

// capturingSigner records the SignRequest passed to Sign.
type capturingSigner struct {
	got signer.SignRequest
}

func (s *capturingSigner) Info(info.Req) (*info.Resp, error) { return nil, nil }
func (s *capturingSigner) Policy() *config.Signing {
	return &config.Signing{Default: &config.SigningProfile{}}
}
func (s *capturingSigner) SetDBAccessor(certdb.Accessor)              {}
func (s *capturingSigner) GetDBAccessor() certdb.Accessor             { return nil }
func (s *capturingSigner) SetPolicy(*config.Signing)                  {}
func (s *capturingSigner) SigAlgo() x509.SignatureAlgorithm           { return x509.UnknownSignatureAlgorithm }
func (s *capturingSigner) SetReqModifier(func(*http.Request, []byte)) {}
func (s *capturingSigner) Sign(req signer.SignRequest) ([]byte, error) {
	s.got = req
	return []byte("dummy-cert"), nil
}

func TestJSONReqToTrueCopiesCRLOverrideAndExtensions(t *testing.T) {
	exts := []signer.Extension{{
		ID:       config.OID{1, 2, 3, 4},
		Critical: true,
		Value:    "deadbeef",
	}}
	js := jsonSignRequest{
		Hosts:       []string{"example.com"},
		Request:     "csr",
		Profile:     "www",
		Label:       "ca",
		CRLOverride: "http://example.com/my.crl",
		Extensions:  exts,
	}

	got := jsonReqToTrue(js)
	if got.CRLOverride != js.CRLOverride {
		t.Fatalf("CRLOverride = %q, want %q", got.CRLOverride, js.CRLOverride)
	}
	if !reflect.DeepEqual(got.Extensions, exts) {
		t.Fatalf("Extensions = %#v, want %#v", got.Extensions, exts)
	}

	js.Hostname = "host.example.com"
	got = jsonReqToTrue(js)
	if got.CRLOverride != js.CRLOverride {
		t.Fatalf("hostname branch CRLOverride = %q, want %q", got.CRLOverride, js.CRLOverride)
	}
	if !reflect.DeepEqual(got.Extensions, exts) {
		t.Fatalf("hostname branch Extensions = %#v, want %#v", got.Extensions, exts)
	}
}

func TestSignHandlerPassesCRLOverrideAndExtensions(t *testing.T) {
	cap := &capturingSigner{}
	handler, err := NewHandlerFromSigner(signer.Signer(cap))
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(handler)
	defer ts.Close()

	csrPEM, err := os.ReadFile(testCSRFile)
	if err != nil {
		t.Fatal(err)
	}

	exts := []signer.Extension{{
		ID:       config.OID{1, 2, 3, 4},
		Critical: false,
		Value:    "deadbeef",
	}}
	blob, err := json.Marshal(jsonSignRequest{
		Request:     string(csrPEM),
		CRLOverride: "http://example.com/my.crl",
		Extensions:  exts,
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.Post(ts.URL, "application/json", bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatal(resp.Status, string(body))
	}

	if cap.got.CRLOverride != "http://example.com/my.crl" {
		t.Fatalf("SignRequest.CRLOverride = %q, want %q", cap.got.CRLOverride, "http://example.com/my.crl")
	}
	if !reflect.DeepEqual(cap.got.Extensions, exts) {
		t.Fatalf("SignRequest.Extensions = %#v, want %#v", cap.got.Extensions, exts)
	}
}
