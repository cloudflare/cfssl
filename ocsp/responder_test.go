package ocsp

import (
	"encoding/hex"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/certdb/sql"
	"github.com/cloudflare/cfssl/certdb/testdb"
	"github.com/cloudflare/cfssl/helpers"

	"github.com/jmhodges/clock"
	goocsp "golang.org/x/crypto/ocsp"
)

const (
	responseFile       = "testdata/resp64.pem"
	binResponseFile    = "testdata/response.der"
	brokenResponseFile = "testdata/response_broken.pem"
	mixResponseFile    = "testdata/response_mix.pem"
)

type testSource struct{}

func (ts testSource) Response(r *goocsp.Request) ([]byte, bool) {
	return []byte("hi"), true
}

type testCase struct {
	method, path string
	expected     int
}

func TestOCSP(t *testing.T) {
	cases := []testCase{
		{"OPTIONS", "/", http.StatusMethodNotAllowed},
		{"GET", "/", http.StatusBadRequest},
		// Bad URL encoding
		{"GET", "%ZZFQwUjBQME4wTDAJBgUrDgMCGgUABBQ55F6w46hhx%2Fo6OXOHa%2BYfe32YhgQU%2B3hPEvlgFYMsnxd%2FNBmzLjbqQYkCEwD6Wh0MaVKu9gJ3By9DI%2F%2Fxsd4%3D", http.StatusBadRequest},
		// Bad URL encoding
		{"GET", "%%FQwUjBQME4wTDAJBgUrDgMCGgUABBQ55F6w46hhx%2Fo6OXOHa%2BYfe32YhgQU%2B3hPEvlgFYMsnxd%2FNBmzLjbqQYkCEwD6Wh0MaVKu9gJ3By9DI%2F%2Fxsd4%3D", http.StatusBadRequest},
		// Bad base64 encoding
		{"GET", "==MFQwUjBQME4wTDAJBgUrDgMCGgUABBQ55F6w46hhx%2Fo6OXOHa%2BYfe32YhgQU%2B3hPEvlgFYMsnxd%2FNBmzLjbqQYkCEwD6Wh0MaVKu9gJ3By9DI%2F%2Fxsd4%3D", http.StatusBadRequest},
		// Bad OCSP DER encoding
		{"GET", "AAAMFQwUjBQME4wTDAJBgUrDgMCGgUABBQ55F6w46hhx%2Fo6OXOHa%2BYfe32YhgQU%2B3hPEvlgFYMsnxd%2FNBmzLjbqQYkCEwD6Wh0MaVKu9gJ3By9DI%2F%2Fxsd4%3D", http.StatusBadRequest},
		// Good encoding all around, including a double slash
		{"GET", "MFQwUjBQME4wTDAJBgUrDgMCGgUABBQ55F6w46hhx%2Fo6OXOHa%2BYfe32YhgQU%2B3hPEvlgFYMsnxd%2FNBmzLjbqQYkCEwD6Wh0MaVKu9gJ3By9DI%2F%2Fxsd4%3D", http.StatusOK},
	}

	responder := Responder{
		Source: testSource{},
		clk:    clock.NewFake(),
	}

	for _, tc := range cases {
		rw := httptest.NewRecorder()

		responder.ServeHTTP(rw, &http.Request{
			Method: tc.method,
			URL: &url.URL{
				Path: tc.path,
			},
		})
		if rw.Code != tc.expected {
			t.Errorf("Incorrect response code: got %d, wanted %d", rw.Code, tc.expected)
		}
	}
}

func TestCacheHeaders(t *testing.T) {
	source, err := NewSourceFromFile(responseFile)
	if err != nil {
		t.Fatalf("Error constructing source: %s", err)
	}

	fc := clock.NewFake()
	fc.Set(time.Date(2015, 11, 12, 0, 0, 0, 0, time.UTC))
	responder := Responder{
		Source: source,
		clk:    fc,
	}

	rw := httptest.NewRecorder()
	responder.ServeHTTP(rw, &http.Request{
		Method: "GET",
		URL: &url.URL{
			Path: "MEMwQTA/MD0wOzAJBgUrDgMCGgUABBSwLsMRhyg1dJUwnXWk++D57lvgagQU6aQ/7p6l5vLV13lgPJOmLiSOl6oCAhJN",
		},
	})
	if rw.Code != http.StatusOK {
		t.Errorf("Unexpected HTTP status code %d", rw.Code)
	}
	testCases := []struct {
		header string
		value  string
	}{
		{"Last-Modified", "Tue, 20 Oct 2015 00:00:00 UTC"},
		{"Expires", "Sun, 20 Oct 2030 00:00:00 UTC"},
		{"Cache-Control", "max-age=471398400, public, no-transform, must-revalidate"},
		{"Etag", "\"8169FB0843B081A76E9F6F13FD70C8411597BEACF8B182136FFDD19FBD26140A\""},
	}
	for _, tc := range testCases {
		headers, ok := rw.HeaderMap[tc.header]
		if !ok {
			t.Errorf("Header %s missing from HTTP response", tc.header)
			continue
		}
		if len(headers) != 1 {
			t.Errorf("Wrong number of headers in HTTP response. Wanted 1, got %d", len(headers))
			continue
		}
		actual := headers[0]
		if actual != tc.value {
			t.Errorf("Got header %s: %s. Expected %s", tc.header, actual, tc.value)
		}
	}

	rw = httptest.NewRecorder()
	headers := http.Header{}
	headers.Add("If-None-Match", "\"8169FB0843B081A76E9F6F13FD70C8411597BEACF8B182136FFDD19FBD26140A\"")
	responder.ServeHTTP(rw, &http.Request{
		Method: "GET",
		URL: &url.URL{
			Path: "MEMwQTA/MD0wOzAJBgUrDgMCGgUABBSwLsMRhyg1dJUwnXWk++D57lvgagQU6aQ/7p6l5vLV13lgPJOmLiSOl6oCAhJN",
		},
		Header: headers,
	})
	if rw.Code != http.StatusNotModified {
		t.Fatalf("Got wrong status code: expected %d, got %d", http.StatusNotModified, rw.Code)
	}
}

func TestNewSourceFromFile(t *testing.T) {
	_, err := NewSourceFromFile("")
	if err == nil {
		t.Fatal("Didn't fail on non-file input")
	}

	// expected case
	_, err = NewSourceFromFile(responseFile)
	if err != nil {
		t.Fatal(err)
	}

	// binary-formatted file
	_, err = NewSourceFromFile(binResponseFile)
	if err != nil {
		t.Fatal(err)
	}

	// the response file from before, with stuff deleted
	_, err = NewSourceFromFile(brokenResponseFile)
	if err != nil {
		t.Fatal(err)
	}

	// mix of a correct and malformed responses
	_, err = NewSourceFromFile(mixResponseFile)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSqliteTrivial(t *testing.T) {
	// First, read and parse certificate and issuer files needed to make
	// an OCSP request.
	certFile := "testdata/sqlite_ca.pem"
	issuerFile := "testdata/ca.pem"
	certContent, err := ioutil.ReadFile(certFile)
	if err != nil {
		t.Errorf("Error reading cert file: %s", err)
	}
	issuerContent, err := ioutil.ReadFile(issuerFile)
	if err != nil {
		t.Errorf("Error reading issuer file: %s", err)
	}
	cert, err := helpers.ParseCertificatePEM(certContent)
	if err != nil {
		t.Errorf("Error parsing cert file: %s", err)
	}
	issuer, err := helpers.ParseCertificatePEM(issuerContent)
	if err != nil {
		t.Errorf("Error parsing cert file: %s", err)
	}

	// Next, create the OCSP request.
	reqByte, err := goocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		t.Errorf("Error creating OCSP request: %s", err)
	}
	req, err := goocsp.ParseRequest(reqByte)
	if err != nil {
		t.Errorf("Error parsing OCSP request: %s", err)
	}

	sqliteDBfile := "testdata/sqlite_test.db"
	db := testdb.SQLiteDB(sqliteDBfile)
	accessor := sql.NewAccessor(db)

	// Populate the DB with the OCSPRecord, and check
	// that Response() handles the request appropiately.
	ocsp := certdb.OCSPRecord{
		AKI:    hex.EncodeToString(req.IssuerKeyHash),
		Body:   "Test OCSP",
		Expiry: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		Serial: req.SerialNumber.String(),
	}
	err = accessor.InsertOCSP(ocsp)
	if err != nil {
		t.Errorf("Error inserting OCSP record into DB: %s", err)
	}

	// Use the created Accessor to create a new DBSource.
	src := NewDBSource(accessor)

	// Call Response() method on constructed request and check the output.
	response, present := src.Response(req)
	if !present {
		t.Error("No response present for given request")
	}
	if string(response) != "Test OCSP" {
		t.Error("Incorrect response received from Sqlite DB")
	}
}

func TestSqliteRealResponse(t *testing.T) {
	sqliteDBfile := "testdata/sqlite_test.db"
	db := testdb.SQLiteDB(sqliteDBfile)
	accessor := sql.NewAccessor(db)

	certFile := "testdata/cert.pem"
	issuerFile := "testdata/ca.pem"
	certContent, err := ioutil.ReadFile(certFile)
	if err != nil {
		t.Errorf("Error reading cert file: %s", err)
	}
	issuerContent, err := ioutil.ReadFile(issuerFile)
	if err != nil {
		t.Errorf("Error reading issuer file: %s", err)
	}
	cert, err := helpers.ParseCertificatePEM(certContent)
	if err != nil {
		t.Errorf("Error parsing cert file: %s", err)
	}
	issuer, err := helpers.ParseCertificatePEM(issuerContent)
	if err != nil {
		t.Errorf("Error parsing cert file: %s", err)
	}

	// Create an OCSP request.
	reqByte, err := goocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		t.Errorf("Error creating OCSP request: %s", err)
	}
	req, err := goocsp.ParseRequest(reqByte)
	if err != nil {
		t.Errorf("Error parsing OCSP request: %s", err)
	}

	// Create the template to be used in making an OCSP response.
	template := goocsp.Response{
		Status:       goocsp.Good,
		SerialNumber: req.SerialNumber,
		ThisUpdate:   time.Now(),
		NextUpdate:   time.Now().AddDate(0, 1, 0),
	}
	keyPEM, err := ioutil.ReadFile("testdata/ca-key.pem")
	if err != nil {
		t.Errorf("Error reading private key file: %s", err)
	}
	priv, err := helpers.ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		t.Errorf("Error parsing private key: %s", err)
	}

	// Create an OCSP response to be inserted into the DB.
	response, err := goocsp.CreateResponse(issuer, cert, template, priv)
	if err != nil {
		t.Errorf("Error creating OCSP response: %s", err)
	}

	// Create record for the OCSP response and add the record to the DB.
	ocsp := certdb.OCSPRecord{
		AKI:    hex.EncodeToString(req.IssuerKeyHash),
		Body:   string(response),
		Expiry: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		Serial: req.SerialNumber.String(),
	}
	err = accessor.InsertOCSP(ocsp)
	if err != nil {
		t.Errorf("Error inserting OCSP record into DB: %s", err)
	}

	// Use the created Accessor to create new DBSource.
	src := NewDBSource(accessor)

	// Call Response() method on constructed request and check the output.
	response, present := src.Response(req)
	if !present {
		t.Error("No response present for given request")
	}
	// Attempt to parse the returned response and make sure it is well formed.
	_, err = goocsp.ParseResponse(response, issuer)
	if err != nil {
		t.Errorf("Error parsing response: %v", err)
	}
}
