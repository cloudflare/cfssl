package main

import (
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// 'cfssl -help' should be supported.
func TestHelp(t *testing.T) {
	called := false
	ResetForTesting(func() { called = true })
	os.Args = []string{"cfssl", "-help"}
	main()
	if !called {
		t.Fatal("flag -help is not recognized correctly.")
	}

}

// 'cfssl -badflag' should trigger parse error and usage invocation.
func TestUnknownFlag(t *testing.T) {
	called := false
	os.Args = []string{"cfssl", "-badflag"}
	ResetForTesting(func() { called = true })
	main()
	if !called {
		t.Fatal("Bad flag is not caught.")
	}

}

// 'cfssl badcommand' should trigger parse error and usage invocation.
func TestBadCommand(t *testing.T) {
	called := false
	ResetForTesting(func() { called = true })
	os.Args = []string{"cfssl", "badcommand"}
	main()
	if !called {
		t.Fatal("Bad command is not caught.")
	}
}

func TestCommandHelp(t *testing.T) {
	called := false
	ResetCFSSLFlagSetForTesting(func() { called = true })
	args := []string{"-help"}
	cfsslFlagSet.Parse(args)
	if !called {
		t.Fatal("sub-command -help is not recognized.")
	}

}

func TestCommandBadFlag(t *testing.T) {
	called := false
	ResetCFSSLFlagSetForTesting(func() { called = true })
	args := []string{"-help", "-badflag"}
	cfsslFlagSet.Parse(args)
	if !called {
		t.Fatal("bad flag for sub-command is not caught.")
	}
}

func TestServe(t *testing.T) {
	args := []string{"-ca", "empty", "-ca-key", "empty", "-ca-bundle", "empty", "-int-bundle ", "empty"}
	cfsslFlagSet.Parse(args)
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

// Additional routines derived from flag unit testing

// ResetForTesting clears all flag state and sets the usage function as directed.
// After calling ResetForTesting, parse errors in flag handling will not
// exit the program.
func ResetForTesting(usage func()) {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flag.Usage = usage
}

// ResetCFSSLFlagSetForTesting reset cfsslFlagSet with flag.ContinueOnError so parse
// errors in flag will not exit the program
func ResetCFSSLFlagSetForTesting(usage func()) {
	cfsslFlagSet = flag.NewFlagSet("cfssl", flag.ContinueOnError)
	registerFlags()
	cfsslFlagSet.Usage = usage
}
