package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/auth"
	"github.com/cloudflare/cfssl/certinfo"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers/testsuite"
	"github.com/cloudflare/cfssl/info"
	"github.com/cloudflare/cfssl/scan"
)

// CFSSL local server to start up
var server *testsuite.CFSSLServer

// We will test on this address and port.
const addressToTest = "127.0.0.1"
const portToTest = 8888

// This is the generic endpoint for our server
var postStr = fmt.Sprintf("http://%s:%s/api/v1/cfssl/", addressToTest, strconv.Itoa(portToTest))

// Var which holds the CA Request which is used to create our CA
// Certificate to start CFSSL server
var (
	keyRequest = csr.BasicKeyRequest{
		A: "rsa",
		S: 2048,
	}
	CAConfig = csr.CAConfig{
		PathLength: 1,
		Expiry:     "1/1/2016",
	}
	CARequest = csr.CertificateRequest{
		CN: "example.com",
		Names: []csr.Name{
			{
				C:  "US",
				ST: "California",
				L:  "San Francisco",
				O:  "Internet Widgets, LLC",
				OU: "Certificate Authority",
			},
		},
		Hosts:      []string{"ca.example.com"},
		KeyRequest: &keyRequest,
		CA:         &CAConfig,
	}
)

// We will Unmarshal API and CLI outputs into the following structs

// Bundle resulting struct is not defined in bundler/bundle.go. A custom
// bundle struct will be made here for convenience.
type CLIBundleResponse struct {
	Bundle string `json:"bundle"`
	CRT    string `json:"crt"`
	Root   string `json:"root"`
}

type APIBundleResponse struct {
	Success bool `json:"success"`
	Result  struct {
		CLIBundleResponse
	} `json:"result"`
}

// Scan struct utilizes ScannerResult struct defined in
// scan/scan_common.go.
type CLIScanResponse struct {
	TLSHandshake struct {
		CertsByCiphers struct {
			scan.ScannerResult
		} `json:"CertsByCiphers"`
		CertsBySigAlgs struct {
			scan.ScannerResult
		} `json:"CertsBySigAlgs"`
		SigAlgs struct {
			scan.ScannerResult
		} `json:"SigAlgs"`
	} `json:"TLSHandshake"`
}

type APIScanResponse struct {
	Success bool `json:"success"`
	Result  struct {
		CLIScanResponse
	} `json:"result"`
}

// API Struct for CertInfo utilizes certinfo.Certificate struct.
type APICertInfoResponse struct {
	Success bool `json:"success"`
	Result  struct {
		certinfo.Certificate
	} `json:"result"`
}

// API Struct for Sign and Info will utilize info.Resp struct (for the
// "certificate" field)
type APIResponse struct {
	Success bool `json:"success"`
	Result  struct {
		info.Resp
	} `json:"result"`
}

// CFSSL Sign on CLI returns a json with a "cert" field, not "certificate"
// as is with the Sign API response struct defined in scan_common.go.
// The following struct is made to suit that situation.
type CLISignResponse struct {
	Certificate string `json:"cert"`
}

// Start up the CFSSL local server.
func setup() {
	// Set up a test server using our CA certificate and key.
	CACert, CAKey, err := testsuite.CreateSelfSignedCert(CARequest)
	if err != nil {
		panic(err)
	}
	// Set up a test server using our CA certificate and key.
	serverData := testsuite.CFSSLServerData{CA: CACert, CAKey: CAKey}
	server, err = testsuite.StartCFSSLServer(addressToTest, portToTest,
		serverData)
	if err != nil {
		setdown()
		panic(err)
	}
}

// Kill the CFSSL local server.
func setdown() {
	err := server.Kill()
	if err != nil {
		panic(err)
	}
}

// Return API output
func apiOut(request string, jsonStr []byte, endpoint string, t *testing.T) []byte {
	setup()
	// Generate request
	req, err := http.NewRequest(request, endpoint, bytes.NewBuffer(jsonStr))
	if err != nil {
		setdown()
		t.Fatalf("Error creating new HTTP request, %v", err)
	}
	client := &http.Client{}
	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		setdown()
		t.Fatalf("Error sending request to client, %v", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		setdown()
		t.Fatalf("Error reading API response, %v", err)
	}
	setdown()
	// return API response to the request
	return body
}

// Return CLI output
func cliOut(command *exec.Cmd, t *testing.T) []byte {
	CLIOutput, err := command.Output()
	if err != nil {
		t.Fatalf("Error sending request %s to cli, %v",
			string(CLIOutput), err)
	}
	return []byte(CLIOutput)
}

// Format the API/CLI Output into the following structs
func apiFormat(body []byte, t *testing.T) APIResponse {
	apiRes := APIResponse{}
	err := json.Unmarshal(body, &apiRes)
	if err != nil {
		t.Fatalf("Error Unmarshalling %s", string(body))
	}
	return apiRes
}

func apiFormat2(body []byte, t *testing.T) api.Response {
	res := api.Response{}
	err := json.Unmarshal(body, &res)
	if err != nil {
		t.Fatalf("Error Unmarshalling %s", string(body))
	}
	return res
}

// START OF TESTS

// Testing the Bundle API against CFSSL Bundle CLI
func TestBundle(t *testing.T) {
	// bundleAPIResp holds response from bundle endpoint
	jsonStr := []byte(`{"domain": "cloudflare.com"}`)
	body := apiOut("POST", jsonStr, postStr+"bundle", t)
	bundleAPIResp := APIBundleResponse{}
	err := json.Unmarshal(body, &bundleAPIResp)
	if err != nil {
		t.Fatalf("Error Unmarshalling %s into bundleAPIResp", string(body))
	}

	// bundleCLIResp holds response from cfssl bundle (command line)
	command := exec.Command("cfssl", "bundle", "-domain=cloudflare.com")
	body = cliOut(command, t)
	bundleCLIResp := CLIBundleResponse{}
	err = json.Unmarshal(body, &bundleCLIResp)
	if err != nil {
		t.Fatalf("Error Unmarshalling %s into bundleCLIResp", string(body))
	}

	if !bundleAPIResp.Success {
		t.Fatalf("Bundle API Request Failed.")
	}
	// Checks for correctness between API and CLI responses
	if !reflect.DeepEqual(bundleAPIResp.Result.Bundle,
		bundleCLIResp.Bundle) {
		t.Fatalf("Bundle API Bundle did not match with CLI")
	}
	if !reflect.DeepEqual(bundleAPIResp.Result.CRT, bundleCLIResp.CRT) {
		t.Fatalf("Bundle API CRT did not match with CLI")
	}
	if !reflect.DeepEqual(bundleAPIResp.Result.Root, bundleCLIResp.Root) {
		t.Fatalf("Bundle API Root did not match with CLI")
	}
}

// Sign Test: Since cfssl sign generates different certificates each time,
// (each cert gets a distinct serial number) there is no way to check
// "correctness" of a certificate from API to CLI.
// Therefore, in TestSign, we just check for successful output.
func TestSign(t *testing.T) {
	signReq, err := ioutil.ReadFile("testdata/signRequest.json")
	if err != nil {
		t.Fatalf("Error reading signRequest.json file")
	}
	response := apiOut("POST", signReq, postStr+"sign", t)
	signAPIResp := apiFormat(response, t)
	if !signAPIResp.Success {
		t.Fatalf("Sign API Failed Response")
	}
}

// Testing the Scan API against CFSSL Scan CLI
func TestScan(t *testing.T) {
	// scanAPIResp holds response from cfssl scan using scan endpoint
	body := apiOut("GET", nil, postStr+"scan?host=cloudflare.com", t)
	scanAPIResp := APIScanResponse{}
	err := json.Unmarshal(body, &scanAPIResp)
	if err != nil {
		t.Fatalf("Error Unmarshalling %s into scanAPIResp", string(body))
	}

	// scanCLIResp holds response from cfssl scan (command line)
	command := exec.Command("cfssl", "scan", "cloudflare.com")
	body = cliOut(command, t)
	index := strings.Index(string(body), "{")
	cliout := string(body)[index:]
	scanCLIResp := CLIScanResponse{}
	err = json.Unmarshal([]byte(cliout), &scanCLIResp)
	if err != nil {
		t.Fatalf("Error Unmarshalling %s into scanCLIResp", string(body))
	}

	if !scanAPIResp.Success {
		t.Fatalf("Scan API Request Failed")
	}
	// Checks for correctness between API and CLI responses
	if !reflect.DeepEqual(scanAPIResp.Result.TLSHandshake, scanCLIResp.TLSHandshake) {
		t.Fatalf("Scan API TLSHandshake (%s) did not match with CLI (%s)",
			scanAPIResp.Result.TLSHandshake, scanCLIResp.TLSHandshake)
	}
}

// Testing the CertInfo API against CFSSL CertInfo CLI
func TestCertInfo(t *testing.T) {
	// certinfoAPIResp holds response from cfssl certinfo using endpoint
	jsonStr := []byte(`{"domain": "cloudflare.com"}`)
	body := apiOut("POST", jsonStr, postStr+"certinfo", t)
	certinfoAPIResp := APICertInfoResponse{}
	err := json.Unmarshal(body, &certinfoAPIResp)
	if err != nil {
		t.Fatalf("Error Unmarshalling %s into certinfoAPIResp", string(body))
	}

	// certinfoCLIResp holds response from cfssl certinfo (command line)
	command := exec.Command("cfssl", "certinfo", "-domain=cloudflare.com")
	body = cliOut(command, t)
	certinfoCLIResp := certinfo.Certificate{}
	err = json.Unmarshal(body, &certinfoCLIResp)
	if err != nil {
		t.Fatalf("Error Unmarshalling %s into certinfoCLIResp", string(body))
	}

	if !certinfoAPIResp.Success {
		t.Fatalf("CertInfo API Request Failed")
	}
	// Checks for correctness between API and CLI responses
	if !reflect.DeepEqual(certinfoAPIResp.Result.RawPEM,
		certinfoCLIResp.RawPEM) {
		t.Fatalf("CertInfo API Pem did not match with CLI")
	}
	if !reflect.DeepEqual(certinfoAPIResp.Result.Subject,
		certinfoCLIResp.Subject) {
		t.Fatalf("CertInfo API Subject did not match with CLI")
	}
	if !reflect.DeepEqual(certinfoAPIResp.Result.SignatureAlgorithm,
		certinfoCLIResp.SignatureAlgorithm) {
		t.Fatalf("CertInfo API Sigalg did not match with CLI")
	}
}

// CFSSL info test to get information about the remote (local) server.
// Since we need the server to be up for both API and CLI outputs,
// apiOut and cliOut is not called
func TestInfo(t *testing.T) {
	jsonStr := []byte(`{"label": "127.0.0.1:8888"}`)
	setup()
	req, _ := http.NewRequest("POST", postStr+"info",
		bytes.NewBuffer(jsonStr))
	client := &http.Client{}
	resp, _ := client.Do(req)
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	// infoAPIResp holds response from cfssl info using info endpoint
	infoAPIResp := apiFormat(body, t)

	// infoCLIResp holds response from cfssl info (command line)
	command := exec.Command("cfssl", "info", "-remote=127.0.0.1:8888")
	infoCLIResp := info.Resp{}
	body = cliOut(command, t)
	err := json.Unmarshal(body, &infoCLIResp)
	if err != nil {
		t.Fatalf("Error Unmarshalling %s into infoCLIResp", string(body))
	}
	setdown()

	if !infoAPIResp.Success {
		t.Fatalf("Info API Failed Response")
	}
	// Checks for correctness between API and CLI responses
	if !reflect.DeepEqual(infoAPIResp.Result.Certificate,
		infoCLIResp.Certificate) {
		t.Fatalf("Info API Certificate did not match with CLI")
	}
}

// Below are API endpoints without a CLI counterpart.
// They are currently being checked for just successful output,
// not necessarily matching any existing CLI output.
func TestScanInfo(t *testing.T) {
	response := apiOut("GET", nil, postStr+"scaninfo", t)
	scaninfoAPIResp := apiFormat2(response, t)
	if !scaninfoAPIResp.Success {
		t.Fatalf("ScanInfo API Failed Response")
	}
}

func TestInitCA(t *testing.T) {
	keyReq, err := ioutil.ReadFile("testdata/newkeyRequest.json")
	if err != nil {
		t.Fatalf("Error reading newkeyRequest.json file")
	}
	response := apiOut("POST", keyReq, postStr+"init_ca", t)
	initcaAPIResp := apiFormat2(response, t)
	if !initcaAPIResp.Success {
		t.Fatalf("InitCA API Failed Response")
	}
}

func TestNewCert(t *testing.T) {
	newcertReq, err := ioutil.ReadFile("testdata/newcertRequest.json")
	if err != nil {
		t.Fatalf("Error reading newcertRequest.json file")
	}
	jsonStr := []byte(`{ "request": ` + string(newcertReq) + ` }`)
	response := apiOut("POST", jsonStr, postStr+"newcert", t)
	newcertAPIResp := apiFormat2(response, t)
	if !newcertAPIResp.Success {
		t.Fatalf("NewCert API Failed Response")
	}
}

func TestNewKey(t *testing.T) {
	keyReq, err := ioutil.ReadFile("testdata/newkeyRequest.json")
	if err != nil {
		t.Fatalf("Error reading newkeyRequest.json file")
	}
	response := apiOut("POST", keyReq, postStr+"newkey", t)
	newkeyAPIResp := apiFormat2(response, t)
	if !newkeyAPIResp.Success {
		t.Fatalf("NewKey API Failed Response")
	}
}

func TestAuthSign(t *testing.T) {
	// random key string generated from open('/dev/random').read(32).encode('hex')
	authkey := "f66761a3098baaa7c893412d54557b8ff22e69eb4f26f958b769ff6ff7f7271b"

	csr, _ := ioutil.ReadFile("testdata/authsignRequest.json")

	testProvider, _ := auth.New(authkey, nil)

	token, _ := testProvider.Token(csr)
	request := base64.StdEncoding.EncodeToString(csr)

	jsonStr := []byte(`{
	    "timestamp": 1447094758,
	    "token": "` + base64.StdEncoding.EncodeToString(token) + `",
	    "request": "` + request + `"
    }`)

	req, _ := http.NewRequest("POST", postStr+"authsign",
		bytes.NewBuffer(jsonStr))
	client := &http.Client{}

	// Start up server + Execute request
	// Note that we are using a custom config file
	// with the authkey above specified (inside config file)
	cmd := exec.Command("cfssl", "serve", "-address="+addressToTest,
		"-port="+strconv.Itoa(portToTest), "-ca=testdata/cert.pem",
		"-ca-key=testdata/cert-key.pem", "-config=testdata/config.json")
	if err := cmd.Start(); err != nil {
		t.Fatalf("Error running cfssl serve, %v", err)
	}

	// Give the server time to start up
	time.Sleep(500 * time.Millisecond)

	resp, _ := client.Do(req)
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	// Close the server
	cmd.Process.Kill()

	// Unmarshal the response
	signAPIResp := apiFormat(body, t)
	if !signAPIResp.Success {
		t.Fatalf("AuthSign API Failed Response")
	}
}
