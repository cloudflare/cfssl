package ocsp

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/ocsp"
)

const (
	noCacheHeader = "public, max-age=0, no-cache"
)

func TestResponderCacheControlBadReq(t *testing.T) {
	source := make(InMemorySource)

	r := Responder{
		Source:              source,
		NoCacheOnBadRequest: true,
		NoCacheOnNotFound:   true,
	}

	methods := []string{"BOGUS", "GET", "POST"}
	for _, m := range methods {
		rWriter := httptest.NewRecorder()
		r.ServeHTTP(rWriter, &http.Request{
			Method: m,
		})
		cacheHeader := rWriter.Header().Get("Cache-Control")
		if cacheHeader != noCacheHeader {
			t.Fatal(fmt.Sprintf("Incorrect cache control header returned: %s", cacheHeader))
		}
	}

	r.NoCacheOnBadRequest = false
	for _, m := range methods {
		rWriter := httptest.NewRecorder()
		r.ServeHTTP(rWriter, &http.Request{
			Method: m,
		})
		cacheHeader := rWriter.Header().Get("Cache-Control")
		if cacheHeader != "" {
			t.Fatal(fmt.Sprintf("Incorrect cache control header returned: %s", cacheHeader))
		}
	}

	// Check for not found POST/GET

	// Re-check with flipped flag
	r.NoCacheOnNotFound = false
}

func TestResponderCacheControlCacheNotFound(t *testing.T) {
	source := make(InMemorySource)

	r := Responder{
		Source: source,
	}

	issuerBytes, err := ioutil.ReadFile(serverCertFile)
	if err != nil {
		t.Fatal(err)
	}
	issuerPEM, _ := pem.Decode(issuerBytes)
	issuer, err := x509.ParseCertificate(issuerPEM.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	certBytes, err := ioutil.ReadFile(otherCertFile)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, _ := pem.Decode(certBytes)
	cert, err := x509.ParseCertificate(certPEM.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	ocspBytes, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		t.Fatal(err)
	}
	b64req := base64.URLEncoding.EncodeToString(ocspBytes)

	rWriter := httptest.NewRecorder()
	r.ServeHTTP(rWriter, &http.Request{
		Method: "POST",
		Body:   ioutil.NopCloser(strings.NewReader(string(ocspBytes))),
	})
	cacheHeader := rWriter.Header().Get("Cache-Control")
	if cacheHeader != "" {
		t.Fatal(fmt.Sprintf("Incorrect cache control header returned: %s", cacheHeader))
	}

	rWriter = httptest.NewRecorder()
	r.ServeHTTP(rWriter, &http.Request{
		Method:     "GET",
		RequestURI: fmt.Sprintf("/%s", b64req),
	})
	cacheHeader = rWriter.Header().Get("Cache-Control")
	if cacheHeader != "" {
		t.Fatal(fmt.Sprintf("Incorrect cache control header returned: %s", cacheHeader))
	}

	r.NoCacheOnNotFound = true
	rWriter = httptest.NewRecorder()
	r.ServeHTTP(rWriter, &http.Request{
		Method: "POST",
		Body:   ioutil.NopCloser(strings.NewReader(string(ocspBytes))),
	})
	cacheHeader = rWriter.Header().Get("Cache-Control")
	if cacheHeader != noCacheHeader {
		t.Fatal(fmt.Sprintf("Incorrect cache control header returned: %s", cacheHeader))
	}

	rWriter = httptest.NewRecorder()
	r.ServeHTTP(rWriter, &http.Request{
		Method:     "GET",
		RequestURI: fmt.Sprintf("/%s", b64req),
	})
	cacheHeader = rWriter.Header().Get("Cache-Control")
	if cacheHeader != noCacheHeader {
		t.Fatal(fmt.Sprintf("Incorrect cache control header returned: %s", cacheHeader))
	}
}
