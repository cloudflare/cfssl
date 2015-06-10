package serve

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServe(t *testing.T) {
	registerHandlers()
	ts := httptest.NewServer(http.DefaultServeMux)
	// Soft-enable endpoints should be all disabled due to empty config files.
	urlSign := ts.URL + "/api/v1/cfssl/sign"
	urlGencert := ts.URL + "/api/v1/cfssl/gencert"
	urlBundle := ts.URL + "/api/v1/cfssl/bundle"
	urlInitCA := ts.URL + "/api/v1/cfssl/init_ca"
	urlCSR := ts.URL + "/api/v1/cfssl/newkey"

	// Disabled endpoint should return "404: Not Found"
	resp, _ := http.Get(urlSign)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatal(resp.Status)
	}

	resp, _ = http.Get(urlGencert)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatal(resp.Status)
	}

	resp, _ = http.Get(urlBundle)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatal(resp.Status)
	}

	// Enabled endpoint should return "405 Method Not Allowed"
	resp, _ = http.Get(urlInitCA)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatal(resp.Status)
	}

	resp, _ = http.Get(urlCSR)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatal(resp.Status)
	}

}
