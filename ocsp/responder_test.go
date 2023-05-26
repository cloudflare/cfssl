package ocsp

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
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

func (ts testSource) Response(r *goocsp.Request) ([]byte, http.Header, error) {
	return []byte("hi"), nil, nil
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
		// Good request, leading slash
		{"GET", "/MFQwUjBQME4wTDAJBgUrDgMCGgUABBQ55F6w46hhx%2Fo6OXOHa%2BYfe32YhgQU%2B3hPEvlgFYMsnxd%2FNBmzLjbqQYkCEwD6Wh0MaVKu9gJ3By9DI%2F%2Fxsd4%3D", http.StatusOK},
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

var testResp = `308204f90a0100a08204f2308204ee06092b0601050507300101048204df308204db3081a7a003020100a121301f311d301b06035504030c146861707079206861636b65722066616b65204341180f32303135303932333231303630305a306c306a3042300906052b0e03021a0500041439e45eb0e3a861c7fa3a3973876be61f7b7d98860414fb784f12f96015832c9f177f3419b32e36ea41890209009cf1912ea8d509088000180f32303135303932333030303030305aa011180f32303330303832363030303030305a300d06092a864886f70d01010b05000382010100c17ed5f12c408d214092c86cb2d6ba9881637a9d5cafb8ddc05aed85806a554c37abdd83c2e00a4bb25b2d0dda1e1c0be65144377471bca53f14616f379ee0c0b436c697b400b7eba9513c5be6d92fbc817586d568156293cfa0099d64585146def907dee36eb650c424a00207b01813aa7ae90e65045339482eeef12b6fa8656315da8f8bb1375caa29ac3858f891adb85066c35b5176e154726ae746016e42e0d6016668ff10a8aa9637417d29be387a1bdba9268b13558034ab5f3e498a47fb096f2e1b39236b22956545884fbbed1884f1bc9686b834d8def4802bac8f79924a36867af87412f808977abaf6457f3cda9e7eccbd0731bcd04865b899ee41a08203193082031530820311308201f9a0030201020209009cf1912ea8d50908300d06092a864886f70d01010b0500301f311d301b06035504030c146861707079206861636b65722066616b65204341301e170d3135303430373233353033385a170d3235303430343233353033385a301f311d301b06035504030c146861707079206861636b65722066616b6520434130820122300d06092a864886f70d01010105000382010f003082010a0282010100c20a47799a05c512b27717633413d770f936bf99de62f130c8774d476deac0029aa6c9d1bb519605df32d34b336394d48e9adc9bbeb48652767dafdb5241c2fc54ce9650e33cb672298888c403642407270cc2f46667f07696d3dd62cfd1f41a8dc0ed60d7c18366b1d2cd462d34a35e148e8695a9a3ec62b656bd129a211a9a534847992d005b0412bcdffdde23085eeca2c32c2693029b5a79f1090fe0b1cb4a154b5c36bc04c7d5a08fa2a58700d3c88d5059205bc5560dc9480f1732b1ad29b030ed3235f7fb868f904fdc79f98ffb5c4e7d4b831ce195f171729ec3f81294df54e66bd3f83d81843b640aea5d7ec64d0905a9dbb03e6ff0e6ac523d36ab0203010001a350304e301d0603551d0e04160414fb784f12f96015832c9f177f3419b32e36ea4189301f0603551d23041830168014fb784f12f96015832c9f177f3419b32e36ea4189300c0603551d13040530030101ff300d06092a864886f70d01010b050003820101001df436be66ff938ccbfb353026962aa758763a777531119377845109e7c2105476c165565d5bbce1464b41bd1d392b079a7341c978af754ca9b3bd7976d485cbbe1d2070d2d4feec1e0f79e8fec9df741e0ea05a26a658d3866825cc1aa2a96a0a04942b2c203cc39501f917a899161dfc461717fe9301fce6ea1afffd7b7998f8941cf76f62def994c028bd1c4b49b17c4d243a6fb058c484968cf80501234da89347108b56b2640cb408e3c336fd72cd355c7f690a15405a7f4ba1e30a6be4a51d262b586f77f8472b207fdd194efab8d3a2683cc148abda7a11b9de1db9307b8ed5a9cd20226f668bd6ac5a3852fd449e42899b7bc915ee747891a110a971`

type testHeaderSource struct {
	headers http.Header
}

func (ts testHeaderSource) Response(r *goocsp.Request) ([]byte, http.Header, error) {
	resp, _ := hex.DecodeString(testResp)
	return resp, ts.headers, nil
}

func TestOverrideHeaders(t *testing.T) {
	headers := http.Header(map[string][]string{
		"Content-Type":  {"yup"},
		"Cache-Control": {"nope"},
		"New":           {"header"},
		"Expires":       {"0"},
		"Last-Modified": {"now"},
		"Etag":          {"mhm"},
	})
	responder := Responder{
		Source: testHeaderSource{headers: headers},
		clk:    clock.NewFake(),
	}

	rw := httptest.NewRecorder()
	responder.ServeHTTP(rw, &http.Request{
		Method: "GET",
		URL:    &url.URL{Path: "MFQwUjBQME4wTDAJBgUrDgMCGgUABBQ55F6w46hhx%2Fo6OXOHa%2BYfe32YhgQU%2B3hPEvlgFYMsnxd%2FNBmzLjbqQYkCEwD6Wh0MaVKu9gJ3By9DI%2F%2Fxsd4%3D"},
	})

	if !reflect.DeepEqual(rw.Header(), headers) {
		t.Fatalf("Unexpected Headers returned: wanted %s, got %s", headers, rw.Header())
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
	certContent, err := os.ReadFile(certFile)
	if err != nil {
		t.Errorf("Error reading cert file: %s", err)
	}
	issuerContent, err := os.ReadFile(issuerFile)
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
	response, _, err := src.Response(req)
	if err != nil {
		t.Error(err)
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
	certContent, err := os.ReadFile(certFile)
	if err != nil {
		t.Errorf("Error reading cert file: %s", err)
	}
	issuerContent, err := os.ReadFile(issuerFile)
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
	keyPEM, err := os.ReadFile("testdata/ca-key.pem")
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
	response, _, err = src.Response(req)
	if err != nil {
		t.Error(err)
	}
	// Attempt to parse the returned response and make sure it is well formed.
	_, err = goocsp.ParseResponse(response, issuer)
	if err != nil {
		t.Errorf("Error parsing response: %v", err)
	}

	// Manually run the query "SELECT max(version_id) FROM goose_db_version;"
	// on testdata/sqlite_test.db after running this test to verify that the
	// DB was properly connected to.

}
func TestNewSqliteSource(t *testing.T) {
	dbpath := "testdata/db-config.json"
	_, err := NewSourceFromDB(dbpath)
	if err != nil {
		t.Errorf("Error connecting to Sqlite DB: %v", err)
	}
}
