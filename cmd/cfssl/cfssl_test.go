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
// Be sure that these are free or the test will fail.
var addressToTest = "127.0.0.1"
var portToTest = 8888
var postStr = fmt.Sprintf("http://%s:%s/api/v1/cfssl/", addressToTest,
	strconv.Itoa(portToTest))

var hosts = []byte(`{"hosts":["www.example.com"],
                     "names":[{"C":"US", "ST":"California", 
                       "L":"San Francisco", "O":"example.com"}],
                     "CN": "www.example.com"}`)

var newcertHosts = []byte(`{"hosts":["www.example.com"],
                     "names":[{"C":"US", "ST":"California", 
                       "L":"San Francisco", "O":"example.com"}],
                     "CN": "www.example.com", 
                     "key":{"algo":"rsa","size":2048}}`)

var requestStr = []byte(`{ "request": ` + string(hosts) + ` }`)

var certRequest = []byte(`{"certificate_request":
	"-----BEGIN CERTIFICATE REQUEST-----\n` +
	`MIIC9zCCAd8CAQAwdjELMAkGA1UEBhMCVVMxETAPBgNVBAoTCEN1c3RvbWVyMRAw\n` +
	`DgYDVQQLEwdXZWJzaXRlMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMRMwEQYDVQQI\n` +
	`EwpDYWxpZm9ybmlhMRUwEwYDVQQDEwxjdXN0b21lci5jb20wggEiMA0GCSqGSIb3\n` +
	`DQEBAQUAA4IBDwAwggEKAoIBAQCjUFyhqcDsdyQnfp5GeUVOQFF32pvPHLrQa4ip\n` +
	`KG6tguTjleZk4HGPN2a6CtTAWbWfZmpeImXz5txHJ8Hm42iC/II8q2L2Jhjo8C1o\n` +
	`CM8/HLz2jDiwmLuN4o0+N/5CKnFYmt91dbOvl81WZLiYiqE14NZMLbYDAkQPb6le\n` +
	`G8s+BuZviWEy0ZUmD+fZ4iNn+anlLeCL7XY9+cnrk684KhK2+80VBvsS8Z68GgFw\n` +
	`4j5h7lKHhn6RShhDctSydY91owmZCkLjW804PKQUZhjREO1YLpBvYO5eoOOIjS/E\n` +
	`7usOmtF2bAqOiwwsvaAl3rB6ivS4et5gtjDAU1tVjXNgD7bvAgMBAAGgPDA6Bgkq\n` +
	`hkiG9w0BCQ4xLTArMCkGA1UdEQQiMCCCDGN1c3RvbWVyLmNvbYIQd3d3LmN1c3Rv\n` +
	`bWVyLmNvbTANBgkqhkiG9w0BAQsFAAOCAQEAJ0UCo1NVcVN7NS7ezB2K96ZsWlpH\n` +
	`+75YTF8zyeGaid3FUzl4Ax1SjfV4lMvbbRqc4AX+EFbt78qe4EbVzTkRAUhGqQCb\n` +
	`/yhkRVuDQC1U4ilAzU89KbcQZ7cQ1NnZmFnemOrhdaRNDHAMKEZkO5HFw76Oa0cv\n` +
	`vQqJLjvxEa6ixQTM+4HmLCBZkO8BYPT8rA0vdFS7QcFj8ySGHgLWXOE4joCSc2Hr\n` +
	`x8kqD+sl5JxWQ03vbcV6Gf/b1n1rfNF6sI9Cmt7U0UA9vVtXKDH42v3MrCBl49UB\n` +
	`IONcxyLRT2fMsfVV2SFuo71g36awI3SMHCWewcHZiwS00SzJcDhhg5+htg==\n` +
	`-----END CERTIFICATE REQUEST-----\n"}`)

// Var which holds the CA Request which is used to create
// our CA Certificate to start CFSSL server
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

// Bundle resulting struct is not defined in bundler/bundle.go.
// A custom bundle struct will be made here for convenience.
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

// Scan struct utilizes ScannerResult struct defined in scan/scan_common.go.
type CLIScanResponse struct {
	Connectivity struct {
		CloudFlareStatus struct {
			scan.ScannerResult
		} `json:"CloudFlareStatus"`
		DNSLookup struct {
			scan.ScannerResult
		} `json:"DNSLookup"`
	} `json:"Connectivity"`
	PKI struct {
		ChainExpiration struct {
			scan.ScannerResult
		} `json:"ChainExpiration"`
		ChainValidation struct {
			scan.ScannerResult
		} `json:"ChainValidation"`
		CipherSuite struct {
			scan.ScannerResult
		} `json:"CipherSuite"`
	} `json:"PKI"`
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

// API Struct for Sign and Info will utilize info.Resp struct
// (for the "certificate" field)
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
	s, err := testsuite.StartCFSSLServer(addressToTest, portToTest, serverData)
	server = s
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
func apiOut(request string, jsonStr []byte,
	endpoint string, t *testing.T) []byte {
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
		t.Fatalf("Error sending request %s to cli, %v", string(CLIOutput), err)
	}
	return []byte(CLIOutput)
}

// Format the API/CLI Output into the following structs
func apiFormat(body []byte) APIResponse {
	apiRes := APIResponse{}
	json.Unmarshal(body, &apiRes)
	return apiRes
}

func responseUnmarshal(body []byte) api.Response {
	res := api.Response{}
	json.Unmarshal(body, &res)
	return res
}

// START OF TESTS

// Testing the Bundle API against CFSSL Bundle CLI
func TestBundle(t *testing.T) {
	// bundleAPIResp holds response from cfssl bundle using bundle endpoint
	jsonStr := []byte(`{"domain": "example.com"}`)
	body := apiOut("POST", jsonStr, postStr+"bundle", t)
	bundleAPIResp := APIBundleResponse{}
	json.Unmarshal(body, &bundleAPIResp)

	// bundleCLIResp holds response from cfssl bundle (command line)
	command := exec.Command("cfssl", "bundle", "-domain=example.com")
	body = cliOut(command, t)
	bundleCLIResp := CLIBundleResponse{}
	json.Unmarshal(body, &bundleCLIResp)

	if !bundleAPIResp.Success {
		t.Fatalf("Bundle API Request Failed.")
	}
	// Checks for correctness between API and CLI responses
	if !reflect.DeepEqual(bundleAPIResp.Result.Bundle, bundleCLIResp.Bundle) {
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
	response := apiOut("POST", certRequest, postStr+"sign", t)
	signAPIResp := apiFormat(response)
	if !signAPIResp.Success {
		t.Fatalf("Sign API Failed Response")
	}
}

// Testing the Scan API against CFSSL Scan CLI
func TestScan(t *testing.T) {
	// scanAPIResp holds response from cfssl scan using scan endpoint
	body := apiOut("GET", nil, postStr+"scan?host=cloudflare.com", t)
	scanAPIResp := APIScanResponse{}
	json.Unmarshal(body, &scanAPIResp)

	// scanCLIResp holds response from cfssl scan (command line)
	command := exec.Command("cfssl", "scan", "cloudflare.com")
	body = cliOut(command, t)
	index := strings.Index(string(body), "{")
	cliout := string(body)[index:]
	scanCLIResp := CLIScanResponse{}
	json.Unmarshal([]byte(cliout), &scanCLIResp)

	if !scanAPIResp.Success {
		t.Fatalf("Scan API Request Failed")
	}
	// Checks for correctness between API and CLI responses
	if !reflect.DeepEqual(scanAPIResp.Result.PKI,
		scanCLIResp.PKI) {
		t.Fatalf("Scan API Connectivity (%s) did not match with CLI (%s)",
			scanAPIResp.Result.PKI, scanCLIResp.PKI)
	}
	if !reflect.DeepEqual(scanAPIResp.Result.TLSHandshake,
		scanCLIResp.TLSHandshake) {
		t.Fatalf("Scan API Connectivity (%s) did not match with CLI (%s)",
			scanAPIResp.Result.TLSHandshake, scanCLIResp.TLSHandshake)
	}
}

// Testing the CertInfo API against CFSSL CertInfo CLI
func TestCertInfo(t *testing.T) {
	// certinfoAPIResp holds response from cfssl certinfo using endpoint
	jsonStr := []byte(`{"domain": "example.com"}`)
	body := apiOut("POST", jsonStr, postStr+"certinfo", t)
	certinfoAPIResp := APICertInfoResponse{}
	json.Unmarshal(body, &certinfoAPIResp)

	// certinfoCLIResp holds response from cfssl certinfo (command line)
	command := exec.Command("cfssl", "certinfo", "-domain=example.com")
	body = cliOut(command, t)
	certinfoCLIResp := certinfo.Certificate{}
	json.Unmarshal(body, &certinfoCLIResp)

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
	req, _ := http.NewRequest("POST", postStr+"info", bytes.NewBuffer(jsonStr))
	client := &http.Client{}
	resp, _ := client.Do(req)
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	// infoAPIResp holds response from cfssl info using info endpoint
	infoAPIResp := apiFormat(body)

	// infoCLIResp holds response from cfssl info (command line)
	command := exec.Command("cfssl", "info", "-remote=127.0.0.1:8888")
	infoCLIResp := info.Resp{}
	body = cliOut(command, t)
	json.Unmarshal(body, &infoCLIResp)
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
	scaninfoAPIResp := responseUnmarshal(response)
	if !scaninfoAPIResp.Success {
		t.Fatalf("ScanInfo API Failed Response")
	}
}

func TestInitCA(t *testing.T) {
	response := apiOut("POST", hosts, postStr+"init_ca", t)
	initcaAPIResp := responseUnmarshal(response)
	if !initcaAPIResp.Success {
		t.Fatalf("InitCA API Failed Response")
	}
}

func TestNewCert(t *testing.T) {
	jsonStr := []byte(`{ "request": ` + string(newcertHosts) + ` }`)
	response := apiOut("POST", jsonStr, postStr+"newcert", t)
	fmt.Println(string(response))
	newcertAPIResp := responseUnmarshal(response)
	if !newcertAPIResp.Success {
		t.Fatalf("NewCert API Failed Response")
	}
}

func TestNewKey(t *testing.T) {
	response := apiOut("POST", hosts, postStr+"newkey", t)
	newkeyAPIResp := responseUnmarshal(response)
	if !newkeyAPIResp.Success {
		t.Fatalf("NewKey API Failed Response")
	}
}

func TestAuthSign(t *testing.T) {
	// random key string generated from open('/dev/random').read(32).encode('hex')
	authkey := "f66761a3098baaa7c893412d54557b8ff22e69eb4f26f958b769ff6ff7f7271b"

	csr := []byte(`{
	    "hosts": [
	        "127.0.0.1"
	    ],
	    "certificate_request": "-----BEGIN CERTIFICATE REQUEST-----\n` +
		`MIHyMIGaAgEAMBYxFDASBgNVBAMTC3Rlc3Qgc2VydmVyMFkwEwYHKoZIzj0CAQYI\n` +
		`KoZIzj0DAQcDQgAENosvCA8k6wJNm16fX2CJlh105I5kJrTCktsDfFKTtejqRQy5\n` +
		`Ypx7mfI7hR5dLxdj9H0WXO/1i/mmoBENYm/GJ6AiMCAGCSqGSIb3DQEJDjETMBEw\n` +
		`DwYDVR0RBAgwBocEfwAAATAKBggqhkjOPQQDAgNHADBEAiBjTbRpcdnSXoj32HIM\n` +
		`mG10OjtcpHPmejabVQBpI3hWxwIgQFqGwGYyf2HfYhTBZUs93GlQqqoeWkvNV4I2\n` +
		`2iSfOek=\n-----END CERTIFICATE REQUEST-----\n",
	    "profile": "server",
	    "label": ""
	}`)

	testProvider, _ := auth.New(authkey, nil)

	token, _ := testProvider.Token(csr)
	request := base64.StdEncoding.EncodeToString(csr)

	jsonStr := []byte(`{
	    "timestamp": 1447094758,
	    "token": "` + base64.StdEncoding.EncodeToString(token) + `",
	    "request": "` + request + `"
    }`)

	req, _ := http.NewRequest("POST", postStr+"authsign", bytes.NewBuffer(jsonStr))
	client := &http.Client{}

	// Start up server + Execute request
	cmd := exec.Command("cfssl", "serve", "-address=127.0.0.1", "-port=8888",
		"-ca=testdata/cert.pem", "-ca-key=testdata/cert-key.pem",
		"-config=testdata/config.json")
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
	signAPIResp := apiFormat(body)
	if !signAPIResp.Success {
		t.Fatalf("AuthSign API Failed Response")
	}
}
