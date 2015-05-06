package generator

import (
	"bytes"
	"encoding/json"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/signer/local"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func csrData(t *testing.T) *bytes.Reader {
	req := &csr.CertificateRequest{
		Names: []csr.Name{
			{
				C:  "US",
				ST: "California",
				L:  "San Francisco",
				O:  "CloudFlare",
				OU: "Systems Engineering",
			},
		},
		CN:    "cloudflare.com",
		Hosts: []string{"cloudflare.com"},
		KeyRequest: &csr.KeyRequest{
			Algo: "ecdsa",
			Size: 256,
		},
	}
	csrBytes, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(csrBytes)
}

func TestGeneratorRESTfulVerbs(t *testing.T) {
	handler, _ := NewHandler(CSRValidate)
	ts := httptest.NewServer(handler)
	data := csrData(t)
	// POST should work.
	req, _ := http.NewRequest("POST", ts.URL, data)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatal(resp.Status)
	}

	// Test GET, PUT, DELETE and whatever, expect 400 errors.
	req, _ = http.NewRequest("GET", ts.URL, data)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatal(resp.Status)
	}
	req, _ = http.NewRequest("PUT", ts.URL, data)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatal(resp.Status)
	}
	req, _ = http.NewRequest("DELETE", ts.URL, data)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatal(resp.Status)
	}
	req, _ = http.NewRequest("WHATEVER", ts.URL, data)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatal(resp.Status)
	}
}

type ResponseEx struct {
}

type errorString struct {
	s string
}

func (e *errorString) Error() string {
	return e.s
}

func (r *ResponseEx) Header() http.Header {
	h := map[string][]string{
		"rsc": []string{"hello", "you"},
	}
	return h
}

func (r *ResponseEx) Write([]byte) (int, error) {
	return 2, &errorString{"error"}
}

func (r *ResponseEx) WriteHeader(int) {

}

func testValidator(req *csr.CertificateRequest) error {
	return nil
}

func TestInvalidHTTP(t *testing.T) {
	var expiry = 1 * time.Minute

	var validSigning = &config.Signing{
		Profiles: map[string]*config.SigningProfile{
			"valid": {
				Usage:  []string{"digital signature"},
				Expiry: expiry,
			},
		},
		Default: &config.SigningProfile{
			Usage:  []string{"digital signature"},
			Expiry: expiry,
		},
	}

	signer2, err5 := local.NewSignerFromFile(testCaFile, testCaKeyFile, validSigning)
	if err5 != nil {
		t.Fatal(err5)
	}

	ghSigner := NewCertGeneratorHandlerFromSigner(CSRValidate, signer2)
	if ghSigner == nil {
		t.Fatalf("%v", ghSigner)
	}

}
