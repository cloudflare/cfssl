package testsuite

import (
	"io/ioutil"
	"os"
	"strconv"
	"testing"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
)

const (
	testDataDirectory = "testdata"
	initCADirectory   = testDataDirectory + string(os.PathSeparator) + "initCA"
	preMadeOutput     = testDataDirectory + string(os.PathSeparator) + "cfssl_output.pem"
	csrFile           = testDataDirectory + string(os.PathSeparator) + "cert_csr.json"
)

var (
	keyRequest = csr.KeyRequest{
		Algo: "rsa",
		Size: 2048,
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
	baseRequest2 = csr.CertificateRequest{
		CN: "test.com",
		Names: []csr.Name{
			{
				C:  "US",
				ST: "Texas",
				L:  "Austin",
				O:  "Internet Widgets, LLC",
				OU: "Certificate Authority",
			},
		},
		Hosts:      []string{"ca.test.com"},
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

func TestCreateCertificateChain(t *testing.T) {

	// N is the number of certificates that will be chained together.
	N := 10

	// We'll use the default signing options.
	opts := SignOptions{}

	// --- TEST: Create a chain of one certificate. --- //

	encodedChainFromCode, _, err := CreateCertificateChain(
		[]csr.CertificateRequest{CARequest}, opts)
	checkError(err, t)

	// Now compare to a pre-made certificate chain using a JSON file containing
	// the same request data.

	CLIOutputFile := preMadeOutput
	CLIOutput, err := ioutil.ReadFile(CLIOutputFile)
	checkError(err, t)
	encodedChainFromCLI, err := cleanCLIOutput(CLIOutput, "cert")
	checkError(err, t)

	chainFromCode, err := helpers.ParseCertificatesPEM(encodedChainFromCode)
	checkError(err, t)
	chainFromCLI, err := helpers.ParseCertificatesPEM(encodedChainFromCLI)
	checkError(err, t)

	if !chainsEqual(chainFromCode, chainFromCLI) {
		unequalFieldSlices := checkFieldsOfChains(chainFromCode, chainFromCLI)
		for i, unequalFields := range unequalFieldSlices {
			if len(unequalFields) > 0 {
				t.Log("The certificate chains held unequal fields for chain " + strconv.Itoa(i))
				t.Log("The following fields were unequal:")
				for _, field := range unequalFields {
					t.Log("\t" + field)
				}
			}
		}
		t.Fatal("Certificate chains unequal.")
	}

	// --- TEST: Create a chain of N certificates. --- //

	// First we make a slice of N requests. We make each slightly different.

	cnGrabBag := []string{"example", "invalid", "test"}
	topLevelDomains := []string{".com", ".net", ".org"}
	subDomains := []string{"www.", "secure.", "ca.", ""}
	countryGrabBag := []string{"USA", "China", "England", "Vanuatu"}
	stateGrabBag := []string{"California", "Texas", "Alaska", "London"}
	localityGrabBag := []string{"San Francisco", "Houston", "London", "Oslo"}
	orgGrabBag := []string{"Internet Widgets, LLC", "CloudFlare, Inc."}
	orgUnitGrabBag := []string{"Certificate Authority", "Systems Engineering"}

	requests := make([]csr.CertificateRequest, N)
	requests[0] = CARequest
	for i := 1; i < N; i++ {
		requests[i] = baseRequest

		cn := randomElement(cnGrabBag)
		tld := randomElement(topLevelDomains)
		subDomain1 := randomElement(subDomains)
		subDomain2 := randomElement(subDomains)
		country := randomElement(countryGrabBag)
		state := randomElement(stateGrabBag)
		locality := randomElement(localityGrabBag)
		org := randomElement(orgGrabBag)
		orgUnit := randomElement(orgUnitGrabBag)

		requests[i].CN = cn + "." + tld
		requests[i].Names = []csr.Name{
			{C: country,
				ST: state,
				L:  locality,
				O:  org,
				OU: orgUnit,
			},
		}
		hosts := []string{subDomain1 + requests[i].CN}
		if subDomain2 != subDomain1 {
			hosts = append(hosts, subDomain2+requests[i].CN)
		}
		requests[i].Hosts = hosts
	}

	// Now we make a certificate chain out of these requests.
	encodedCertChain, _, err := CreateCertificateChain(requests, opts)
	checkError(err, t)

	// To test this chain, we compare the data encoded in each certificate to
	// each request we used to generate the chain.
	chain, err := helpers.ParseCertificatesPEM(encodedCertChain)
	checkError(err, t)

	if len(chain) != len(requests) {
		t.Log("Length of chain: " + strconv.Itoa(len(chain)))
		t.Log("Length of requests: " + strconv.Itoa(len(requests)))
		t.Fatal("Length of chain not equal to length of requests.")
	}

	mismatchOccurred := false
	for i := 0; i < len(chain); i++ {
		certEqualsRequest, unequalFields := certEqualsRequest(chain[i], requests[i])
		if !certEqualsRequest {
			mismatchOccurred = true
			t.Log(
				"Certificate " + strconv.Itoa(i) + " and request " +
					strconv.Itoa(i) + " unequal.",
			)
			t.Log("Unequal fields for index " + strconv.Itoa(i) + ":")
			for _, field := range unequalFields {
				t.Log("\t" + field)
			}
		}
	}

	// TODO: check that each certificate is actually signed by the previous one

	if mismatchOccurred {
		t.Fatal("Unequal certificate(s) and request(s) found.")
	}
}
