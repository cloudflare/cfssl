package serve

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServe(t *testing.T) {
	registerHandlers()
	ts := httptest.NewServer(http.DefaultServeMux)
	defer ts.Close()
	expected := make(map[string]int)
	for endpoint := range v1Endpoints {
		expected[endpoint] = http.StatusOK
	}
	for staticEndpoint := range _escData {
		expected[staticEndpoint] = http.StatusOK
	}

	// Disabled endpoints should return '404 Not Found'
	expected["sign"] = http.StatusNotFound
	expected["authsign"] = http.StatusNotFound
	expected["newcert"] = http.StatusNotFound
	expected["info"] = http.StatusNotFound
	expected["bundle"] = http.StatusNotFound

	// Enabled endpoints should return '405 Method Not Allowed'
	expected["init_ca"] = http.StatusMethodNotAllowed
	expected["newkey"] = http.StatusMethodNotAllowed

	// POST-only endpoints should return '400 Bad Request'
	expected["scan"] = http.StatusBadRequest

	// Non-existent endpoints should return '404 Not Found'
	expected["bad_endpoint"] = http.StatusNotFound
	expected["/bad_endpoint"] = http.StatusNotFound

	for endpoint, status := range expected {
		resp, _ := http.Get(ts.URL + v1APIPath(endpoint))
		if resp.StatusCode != expected[endpoint] {
			t.Fatalf("%s: '%s' (expected '%s')", v1APIPath(endpoint), resp.Status, http.StatusText(status))
		}
	}
}
