package ocsp

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/helpers"

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

func TestResponderCacheControlInMemory(t *testing.T) {
	hour := time.Hour
	source, err := NewSourceFromFile(responseFile, &hour)
	if err != nil {
		t.Fatal(err)
	}
	r := Responder{
		Source:              source,
		NoCacheOnBadRequest: true,
		NoCacheOnNotFound:   true,
	}

	// So we don't actually use this certificate, ocsp.CreateRequest requires a real
	// cert (containing RawSubjectPublicKeyInfo) but NewSourceFromFile doesn't care
	// about the issuer name or hash so we use this cert to satisfy the ocsp method
	certPEM, err := ioutil.ReadFile(otherCertFile)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	// This cert contains the magic serial number the InMemorySource uses to find
	// the correct response
	cert := x509.Certificate{SerialNumber: big.NewInt(373)}

	ocspBytes, err := ocsp.CreateRequest(&cert, issuer, nil)
	if err != nil {
		t.Fatal(err)
	}

	rWriter := httptest.NewRecorder()
	r.ServeHTTP(rWriter, &http.Request{
		Method: "POST",
		Body:   ioutil.NopCloser(strings.NewReader(string(ocspBytes))),
	})
	cacheHeader := rWriter.Header().Get("Cache-Control")
	if cacheHeader != "public, max-age=3600" {
		t.Fatal(fmt.Sprintf("Incorrect cache control header returned: %s", cacheHeader))
	}
}
