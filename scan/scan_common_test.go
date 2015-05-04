package scan

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"testing"

	"github.com/cloudflare/cfssl/helpers/testsuite"
)

var TestingScanner = &Scanner{
	Description: "Tests common scan functions",
	scan: func(host string) (Grade, Output, error) {
		switch host {
		case "bad.example.com:443":
			return Bad, "bad.com", nil
		case "Warning.example.com:443":
			return Warning, "Warning.com", nil
		case "good.example.com:443":
			return Good, "good.com", nil
		case "skipped.example.com:443/0":
			return Skipped, "skipped", nil
		default:
			return Grade(-1), "invalid", fmt.Errorf("scan: invalid grade")
		}
	},
}

var TestingFamily = &Family{
	Description: "Tests the scan_common",
	Scanners: map[string]*Scanner{
		"TestingScanner": TestingScanner,
	},
}

var (
	addr    = "127.0.0.1"
	portTLS = "7070"
	portTCP = "8070"

	certFile = "testdata/cert/cert_chain.crt"
	keyFile  = "testdata/cert/decrypted.ssl.key"
)

func TestCommon(t *testing.T) {
	if TestingFamily.Scanners["TestingScanner"] != TestingScanner {
		t.FailNow()
	}

	var grade Grade
	var output Output
	var err error

	grade, output, err = TestingScanner.Scan("bad.example.com:443")
	if grade != Bad || output.(string) != "bad.com" || err != nil {
		t.FailNow()
	}

	grade, output, err = TestingScanner.Scan("Warning.example.com:443")
	if grade != Warning || output.(string) != "Warning.com" || err != nil {
		t.FailNow()
	}

	grade, output, err = TestingScanner.Scan("good.example.com:443")
	if grade != Good || output.(string) != "good.com" || err != nil {
		t.FailNow()
	}

	grade, output, err = TestingScanner.Scan("skipped.example.com:443/0")
	if grade != Skipped || output.(string) != "skipped" || err != nil {
		t.FailNow()
	}

	_, _, err = TestingScanner.Scan("invalid")
	if err == nil {
		t.FailNow()
	}
}

func TestDefaultFamily(t *testing.T) {

	cert, err := ioutil.ReadFile(certFile)
	if err != nil {
		t.Fatal(err.Error())
	}
	key, err := ioutil.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err.Error())
	}

	tlsServer := testsuite.NewTestServer(http.Server{Addr: net.JoinHostPort(addr, portTLS)})
	err = tlsServer.UseDefaultTLSConfig(cert, key)
	if err != nil {
		t.Fatal(err.Error())
	}
	err = tlsServer.Start()
	if err != nil {
		t.Fatal(err.Error())
	}

	// Kill the server upon completion or failure of the tests.
	defer tlsServer.Kill()

	// === TEST: perform all of the default scans against a TLS server ===== //

	results, err := Default.RunScans(tlsServer.Addr, ".", ".")
	if err != nil {
		t.Fatal(err.Error())
	}
	for family, familyResult := range results {
		// We cannot test broad scans locally.
		if family == "Broad" {
			continue
		}
		for scanner, result := range familyResult {
			if result.Error != "" {
				t.Fatal("An error occurred during the following scan: " +
					"[Family: " + family + ", Scanner: " + scanner +
					", Grade: " + result.Grade + "]")
			}
			if result.Grade != Good.String() {
				t.Fatal("The following scan failed: [Family: " + family +
					", Scanner: " + scanner + ", Grade: " + result.Grade + "]")
			}
		}
	}
}
