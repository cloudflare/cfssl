package testsuite

import (
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/cloudflare/cfssl/bundler"
	"github.com/cloudflare/cfssl/initca"
	"github.com/cloudflare/cfssl/scan"
)

var (
	address   = "127.0.0.1"
	portTLS   = "7050"
	portTCP   = "8050"
	portCFSSL = "9050"
	certFile  = "testdata/cert/cert_chain.crt"
	keyFile   = "testdata/cert/decrypted.ssl.key"
)

func TestStartTestServer(t *testing.T) {

	cert, err := ioutil.ReadFile(certFile)
	checkError(err, t)
	key, err := ioutil.ReadFile(keyFile)
	checkError(err, t)

	// Make and start a TLS server and a TCP server.
	tlsServer := NewTestServer(http.Server{Addr: net.JoinHostPort(address, portTLS)})
	err = tlsServer.UseDefaultTLSConfig(cert, key)
	checkError(err, t)
	err = tlsServer.Start()
	checkError(err, t)
	tcpServer := NewTestServer(http.Server{Addr: net.JoinHostPort(address, portTCP)})
	err = tcpServer.Start()
	checkError(err, t)

	// Kill the servers upon completion or failure of the tests.
	defer func() {
		err = tlsServer.Kill()
		if err != nil {
			t.Log(err.Error())
			t.FailNow()
		}
	}()
	defer func() {
		err = tcpServer.Kill()
		if err != nil {
			t.Log(err.Error())
			t.FailNow()
		}
	}()

	// === TEST: bundle using the test server ============================== //

	newBundler, err := bundler.NewBundler(certFile, certFile)
	checkError(err, t)
	_, err = newBundler.BundleFromRemote("harryharpham.me", address, portTLS, bundler.Optimal)
	checkError(err, t)

	// === TEST: perform all of the default scans on the test server ======= //

	results, err := scan.Default.RunScans(tlsServer.Addr, ".", ".")
	checkError(err, t)
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
			if result.Grade != scan.Good.String() {
				t.Fatal("The following scan failed: [Family: " + family +
					", Scanner: " + scanner + ", Grade: " + result.Grade + "]")
			}
		}
	}

	// === TEST: test the connectivity scan's response to a TCP-only server //

	dnsLookup := scan.Connectivity.Scanners["DNSLookup"]
	tcpDial := scan.Connectivity.Scanners["TCPDial"]
	tlsDial := scan.Connectivity.Scanners["TLSDial"]

	grade, _, err := dnsLookup.Scan(tcpServer.Addr)
	if grade != scan.Good {
		t.Log("TCP server failed DNSLookup scan (grade = " + grade.String() + ")")
		t.FailNow()
	}
	checkError(err, t)

	grade, _, err = tcpDial.Scan(tcpServer.Addr)
	if grade != scan.Good {
		t.Log("TCP server failed TCPDial scan (grade = " + grade.String() + ")")
		t.FailNow()
	}
	checkError(err, t)

	grade, _, err = tlsDial.Scan(tcpServer.Addr)
	if grade != scan.Bad {
		t.Log("TCP server did not fail TLSDial scan (grade = " + grade.String() +
			", error = " + err.Error() + ")")
		t.FailNow()
	}
}

func TestStartCFSSLServer(t *testing.T) {
	// We will test on this address and port. Be sure that these are free or
	// the test will fail.

	CACert, _, CAKey, err := initca.New(&CARequest)
	checkError(err, t)

	// Set up a test server using our CA certificate and key.
	server := CFSSLServer{
		Addr:  address,
		Port:  portCFSSL,
		CA:    CACert,
		CAKey: CAKey,
	}
	err = server.Start()
	checkError(err, t)

	// Kill the server upon either completion or failure of the tests.
	defer func() {
		err = server.Kill()
		checkError(err, t)
	}()

	// Try to start up a second server at the same address and port number. We
	// should get an 'address in use' error.
	server2 := CFSSLServer{
		Addr:  server.Addr,
		Port:  server.Port,
		CA:    CACert,
		CAKey: CAKey,
	}
	err = server2.Start()
	if err == nil || !strings.Contains(err.Error(), "Error occurred on server: address") {
		t.Fatal("Two servers allowed on same address and port.")
	}

	// Now make a request of our server and check that no error occurred.

	// First we need a request to send to our server. We marshall the request
	// into JSON format and write it to a temporary file.
	jsonBytes, err := json.Marshal(baseRequest)
	checkError(err, t)
	tempFile, err := createTempFile(jsonBytes)
	if err != nil {
		os.Remove(tempFile)
		panic(err)
	}

	// Now we make the request and check the output.
	remoteServerString := "-remote=" + net.JoinHostPort(address, portCFSSL)
	command := exec.Command(
		"cfssl", "gencert", remoteServerString, "-hostname="+baseRequest.CN, tempFile)
	CLIOutput, err := command.CombinedOutput()
	os.Remove(tempFile)
	checkError(err, t)
	err = checkCLIOutput(CLIOutput)
	checkError(err, t)
	// The output should contain the certificate, request, and private key.
	_, err = cleanCLIOutput(CLIOutput, "cert")
	checkError(err, t)
	_, err = cleanCLIOutput(CLIOutput, "csr")
	checkError(err, t)
	_, err = cleanCLIOutput(CLIOutput, "key")
	checkError(err, t)
}
