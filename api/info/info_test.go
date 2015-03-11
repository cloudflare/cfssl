package info

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/signer/local"
)

const (
	testCaFile    = "../testdata/ca.pem"
	testCaKeyFile = "../testdata/ca_key.pem"
)

func newTestInfoHandler(t *testing.T) (h http.Handler) {
	signer, err := local.NewSignerFromFile(testCaFile, testCaKeyFile, nil)
	if err != nil {
		t.Fatal(err)
	}

	h, err = NewInfoHandler(signer)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestNewInfoHandler(t *testing.T) {
	newTestInfoHandler(t)
}

func newInfoServer(t *testing.T) *httptest.Server {
	ts := httptest.NewServer(newTestInfoHandler(t))
	return ts
}

func testInfoFile(t *testing.T, req map[string]interface{}) (resp *http.Response, body []byte) {
	ts := newInfoServer(t)
	defer ts.Close()

	blob, err := json.Marshal(req)
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

type infoTest struct {
	RequestObject      map[string]interface{}
	ExpectedHTTPStatus int
	ExpectedSuccess    bool
	ExpectedErrorCode  int
}

var infoTests = []infoTest{
	{
		map[string]interface{}{
			"label":   "",
			"profile": "",
		},
		http.StatusOK,
		true,
		0,
	},
	{
		map[string]interface{}{
			"label":   "badlabel",
			"profile": "",
		},
		http.StatusBadRequest,
		false,
		http.StatusBadRequest,
	},
	{
		map[string]interface{}{
			"label": 123,
		},
		http.StatusBadRequest,
		false,
		http.StatusBadRequest,
	},
}

func TestInfo(t *testing.T) {
	for i, test := range infoTests {
		resp, body := testInfoFile(t, test.RequestObject)
		if resp.StatusCode != test.ExpectedHTTPStatus {
			t.Fatalf("Test %d: expected: %d, have %d", i, test.ExpectedHTTPStatus, resp.StatusCode)
			t.Fatal(resp.Status, test.ExpectedHTTPStatus, string(body))
		}

		message := new(api.Response)
		err := json.Unmarshal(body, message)
		if err != nil {
			t.Fatalf("failed to read response body: %v", err)
			t.Fatal(resp.Status, test.ExpectedHTTPStatus, message)
		}

		if test.ExpectedSuccess != message.Success {
			t.Fatalf("Test %d: expected: %v, have %v", i, test.ExpectedSuccess, message.Success)
			t.Fatal(resp.Status, test.ExpectedHTTPStatus, message)
		}
		if test.ExpectedSuccess == true {
			continue
		}

		if test.ExpectedErrorCode != message.Errors[0].Code {
			t.Fatalf("Test %d: expected: %v, have %v", i, test.ExpectedErrorCode, message.Errors[0].Code)
			t.Fatal(resp.Status, test.ExpectedHTTPStatus, message)
		}

	}
}
