package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers/testsuite"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

var (
	keyRequest = csr.BasicKeyRequest{
		A: "rsa",
		S: 2048,
	}
	CAConfig = csr.CAConfig{
		PathLength: 1,
		Expiry:     "1/1/2016",
	}
	baseRequest = csr.CertificateRequest{
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

func main() {
	/* START UP CFSSL SERVER */
	// We will test on this address and port. Be sure that these are free or
	// the test will fail.
	addressToTest := "127.0.0.1"
	portToTest := 1234
	// Set up a test server using our CA certificate and key.
	CACert, CAKey, err := testsuite.CreateSelfSignedCert(CARequest)
	if err != nil {
		panic(err)
	}
	// Set up a test server using our CA certificate and key.
	serverData := testsuite.CFSSLServerData{CA: CACert, CAKey: CAKey}
	server, err := testsuite.StartCFSSLServer(addressToTest, portToTest, serverData)
	if err != nil {
		//panic(err)
		//server.Kill()
	}

	/* COLLECT API OUTPUT */
	var jsonStr = []byte(`{"domain": "example.com", "flavor": "ubiquitous"}`)
	req, err := http.NewRequest("POST", "http://127.0.0.1:1234/api/v1/cfssl/bundle", bytes.NewBuffer(jsonStr))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	fmt.Println("\n\nAPI OUTPUT:\n\n")
	//fmt.Println("response Status:", resp.Status)
	//fmt.Println("response Headers:", resp.Header)
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("response Body:", string(body))

	/* COLLECT COMMAND LINE OUTPUT */
	// Now make a request of our server and check that no error occurred.
	// First we need a request to send to our server. We marshall the request
	// into JSON format and write it to a temporary file.
	jsonBytes, err := json.Marshal(baseRequest)
	if err != nil {
		panic(err)
	}
	tempFile, err := createTempFile(jsonBytes)
	if err != nil {
		os.Remove(tempFile)
		panic(err)
	}

	// Now we make the request and check the output.
	remoteServerString := "-remote=" + addressToTest + ":" + strconv.Itoa(portToTest)
	fmt.Println("\n\nCLI OUTPUT:\n\n")
	command := exec.Command(
		//"cfssl bundle -domain=example.com")
		"cfssl", "gencert", remoteServerString, "-hostname="+baseRequest.CN, tempFile)
	CLIOutput, err := command.CombinedOutput()
	if err != nil {
		//panic(err)
	}
	fmt.Printf(string(CLIOutput))
	/*
		os.Remove(tempFile)
		err = checkCLIOutput(CLIOutput)
		if err != nil {
			panic(err)
		}
		// The output should contain the certificate, request, and private key.
		_, err = cleanCLIOutput(CLIOutput, "cert")
		if err != nil {
			panic(err)
		}
		_, err = cleanCLIOutput(CLIOutput, "csr")
		if err != nil {
			panic(err)
		}
		_, err = cleanCLIOutput(CLIOutput, "key")
		if err != nil {
			panic(err)
		}*/

	/* DIFF API AND COMMAND LINE OUTPUTS */

	// Finally, kill the server.
	err = server.Kill()
	if err != nil {
		panic(err)
	}
	fmt.Printf("done")
}

// Creates a temporary file with the given data. Returns the file name.
func createTempFile(data []byte) (fileName string, err error) {
	// Avoid overwriting a file in the currect directory by choosing an unused
	// file name.
	baseName := "temp"
	tempFileName := baseName
	tryIndex := 0
	for {
		if _, err := os.Stat(tempFileName); err == nil {
			tempFileName = baseName + strconv.Itoa(tryIndex)
			tryIndex++
		} else {
			break
		}
	}

	readWritePermissions := os.FileMode(0664)
	err = ioutil.WriteFile(tempFileName, data, readWritePermissions)
	if err != nil {
		return "", err
	}

	return tempFileName, nil
}

// Checks the CLI Output for failure.
func checkCLIOutput(CLIOutput []byte) error {
	outputString := string(CLIOutput)
	fmt.Printf("OUTPUT: %s", CLIOutput)
	// Proper output will contain the substring "---BEGIN" somewhere
	failureOccurred := !strings.Contains(outputString, "---BEGIN")
	if failureOccurred {
		fmt.Printf("should not print")
	}
	return nil
}

// Returns the cleaned up PEM encoding for the item specified (for example,
// 'cert' or 'key').
func cleanCLIOutput(CLIOutput []byte, item string) (cleanedOutput []byte, err error) {
	outputString := string(CLIOutput)
	// The keyword will be surrounded by quotes.
	itemString := "\"" + item + "\""
	// We should only search for the keyword beyond this point.
	eligibleSearchIndex := strings.Index(outputString, "{")
	outputString = outputString[eligibleSearchIndex:]
	// Make sure the item is present in the output.
	if strings.Index(outputString, itemString) == -1 {
		fmt.Printf("should not print")
	}
	// We add 2 for the [:"] that follows the item
	startIndex := strings.Index(outputString, itemString) + len(itemString) + 2
	outputString = outputString[startIndex:]
	endIndex := strings.Index(outputString, "\\n\"")
	outputString = outputString[:endIndex]
	outputString = strings.Replace(outputString, "\\n", "\n", -1)

	return []byte(outputString), nil
}
