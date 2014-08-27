package api

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudflare/cfssl/csr"
)

const (
	testCaFile         = "testdata/ca.pem"
	testCaKeyFile      = "testdata/ca_key.pem"
	testCSRFile        = "testdata/csr.pem"
	testBrokenCertFile = "testdata/broken.pem"
	testBrokenCSRFile  = "testdata/broken_csr.pem"
)

func newTestSignHandler(t *testing.T) (h http.Handler) {
	h, err := NewSignHandler(testCaFile, testCaKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestNewSignHandler(t *testing.T) {
	newTestSignHandler(t)
}

func TestNewSignHandlerError(t *testing.T) {
	_, err := NewSignHandler(testCaFile, testBrokenCSRFile)
	if err == nil {
		t.Fatal("Expect error when create a signer with broken file.")
	}
}

func newSignServer(t *testing.T) *httptest.Server {
	ts := httptest.NewServer(newTestSignHandler(t))
	return ts
}

func testSignFile(t *testing.T, hostname, csrFile string) (resp *http.Response, body []byte) {
	ts := newSignServer(t)
	defer ts.Close()
	var csrPEM []byte
	if csrFile != "" {
		var err error
		csrPEM, err = ioutil.ReadFile(csrFile)
		if err != nil {
			t.Fatal(err)
		}
	}
	obj := map[string]string{}
	if len(hostname) > 0 {
		obj["hostname"] = hostname
	}
	if len(csrPEM) > 0 {
		obj["certificate_request"] = string(csrPEM)
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

const (
	testHostName   = "localhost"
	testDomainName = "cloudflare.com"
)

type signTest struct {
	Hostname       string
	CSRFile        string
	ExpectedStatus int
}

var signTests = []signTest{
	{
		testHostName,
		testCSRFile,
		http.StatusOK,
	},
	{
		testDomainName,
		testCSRFile,
		http.StatusOK,
	},
	{
		"",
		testCSRFile,
		http.StatusBadRequest,
	},
	{
		testDomainName,
		"",
		http.StatusBadRequest,
	},
	{
		testDomainName,
		testBrokenCSRFile,
		http.StatusBadRequest,
	},
}

func TestSign(t *testing.T) {
	for _, test := range signTests {
		resp, body := testSignFile(t, test.Hostname, test.CSRFile)
		if resp.StatusCode != test.ExpectedStatus {
			t.Fatal(resp.Status, test.ExpectedStatus, string(body))
		}

	}

}

const (
	testCaBundleFile     = "testdata/ca-bundle.pem"
	testIntBundleFile    = "testdata/int-bundle.pem"
	testLeafCertFile     = "testdata/leaf.pem"
	testLeafKeyFile      = "testdata/leaf.key"
	testLeafWrongKeyFile = "testdata/leaf.badkey"
)

func newTestBundleHandler(t *testing.T) (h http.Handler) {
	h, err := NewBundleHandler(testCaBundleFile, testIntBundleFile)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func newBundleServer(t *testing.T) *httptest.Server {
	ts := httptest.NewServer(newTestBundleHandler(t))
	return ts
}

func testBundleFile(t *testing.T, domain, certFile, keyFile, flavor string) (resp *http.Response, body []byte) {
	ts := newBundleServer(t)
	defer ts.Close()
	var certPEM, keyPEM []byte
	if certFile != "" {
		var err error
		certPEM, err = ioutil.ReadFile(certFile)
		if err != nil {
			t.Fatal(err)
		}
	}
	if keyFile != "" {
		var err error
		keyPEM, err = ioutil.ReadFile(keyFile)
		if err != nil {
			t.Fatal(err)
		}
	}

	obj := map[string]string{"flavor": flavor}
	if len(domain) > 0 {
		obj["domain"] = domain
	}
	if len(certPEM) > 0 {
		obj["certificate"] = string(certPEM)
	}
	if len(keyPEM) > 0 {
		obj["private_key"] = string(keyPEM)
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

func TestNewBundleHandler(t *testing.T) {
	newTestBundleHandler(t)
}

type bundleTest struct {
	Domain         string
	CertFile       string
	KeyFile        string
	Flavor         string
	ExpectedStatus int
}

var bundleTests = []bundleTest{
	// Test bundling with certificate
	{
		"",
		testLeafCertFile,
		"",
		"",
		http.StatusOK,
	},
	{
		"",
		testLeafCertFile,
		"",
		"ubiquitous",
		http.StatusOK,
	},
	{
		"",
		testLeafCertFile,
		"",
		"optimal",
		http.StatusOK,
	},
	{
		"",
		testLeafCertFile,
		testLeafKeyFile,
		"",
		http.StatusOK,
	},
	// Test bundling with remote domain

	// Since we are using test CA and intermediates, it's expected
	// to receive 400 bad request because bundling is not possible.
	{
		"google.com",
		"",
		"",
		"",
		http.StatusBadRequest,
	},
	// Error testing.
	{
		"",
		testLeafCertFile,
		testLeafWrongKeyFile,
		"",
		http.StatusBadRequest,
	},
	{
		"",
		"",
		"",
		"",
		http.StatusBadRequest,
	},
	{
		"",
		testBrokenCertFile,
		"",
		"",
		http.StatusBadRequest,
	},
}

func TestBundle(t *testing.T) {
	for _, test := range bundleTests {
		resp, body := testBundleFile(t, test.Domain, test.CertFile, test.KeyFile, test.Flavor)
		if resp.StatusCode != test.ExpectedStatus {
			t.Fatal(resp.Status, test.ExpectedStatus, string(body))
		}

	}
}

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

func TestInitCARESTfulVerbs(t *testing.T) {
	ts := httptest.NewServer(NewInitCAHandler())
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

func TestGeneratorRESTfulVerbs(t *testing.T) {
	handler, _ := NewGeneratorHandler(CSRValidate)
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
