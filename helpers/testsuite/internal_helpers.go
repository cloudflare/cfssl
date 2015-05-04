// Helper functions used internally in the testsuite package.

package testsuite

import (
	"crypto/x509"
	"errors"
	"io/ioutil"
	"math"
	"math/rand"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/csr"
)

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
	// Proper output will contain the substring "---BEGIN" somewhere
	failureOccurred := !strings.Contains(outputString, "---BEGIN")
	if failureOccurred {
		return errors.New("Failure occurred during CLI execution: " + outputString)
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
		return nil, errors.New("Item " + item + " not found in CLI Output")
	}
	// We add 2 for the [:"] that follows the item
	startIndex := strings.Index(outputString, itemString) + len(itemString) + 2
	outputString = outputString[startIndex:]
	endIndex := strings.Index(outputString, "\\n\"")
	outputString = outputString[:endIndex]
	outputString = strings.Replace(outputString, "\\n", "\n", -1)

	return []byte(outputString), nil
}

// ========== Below are helpers for the test files in this package ========= //

// Compare two x509 certificate chains. We only compare relevant data to
// determine equality.
func chainsEqual(chain1, chain2 []*x509.Certificate) bool {
	if len(chain1) != len(chain2) {
		return false
	}

	for i := 0; i < len(chain1); i++ {
		cert1 := nullifyTimeDependency(chain1[i])
		cert2 := nullifyTimeDependency(chain2[i])
		if !reflect.DeepEqual(cert1, cert2) {
			return false
		}
	}
	return true
}

// When comparing certificates created at different times for equality, we do
// not want to worry about fields which are dependent on the time of creation.
// Thus we nullify these fields before comparing the certificates.
func nullifyTimeDependency(cert *x509.Certificate) *x509.Certificate {
	cert.Raw = nil
	cert.RawTBSCertificate = nil
	cert.RawSubjectPublicKeyInfo = nil
	cert.Signature = nil
	cert.PublicKey = nil
	cert.SerialNumber = nil
	cert.NotBefore = time.Time{}
	cert.NotAfter = time.Time{}
	cert.Extensions = nil
	cert.SubjectKeyId = nil
	cert.AuthorityKeyId = nil

	return cert
}

// Compares two structs and returns a list containing the names of all fields
// for which the two structs hold different values.
func checkFields(struct1, struct2 interface{}, typeOfStructs reflect.Type) []string {
	v1 := reflect.ValueOf(struct1)
	v2 := reflect.ValueOf(struct2)

	var unequalFields []string
	for i := 0; i < v1.NumField(); i++ {
		if !reflect.DeepEqual(v1.Field(i).Interface(), v2.Field(i).Interface()) {
			unequalFields = append(unequalFields, typeOfStructs.Field(i).Name)
		}
	}

	return unequalFields
}

// Runs checkFields on the corresponding elements of chain1 and chain2. Element
// i of the returned slice contains a slice of the fields for which certificate
// i in chain1 had different values than certificate i of chain2.
func checkFieldsOfChains(chain1, chain2 []*x509.Certificate) [][]string {
	minLen := math.Min(float64(len(chain1)), float64(len(chain2)))
	typeOfCert := reflect.TypeOf(*chain1[0])

	var unequalFields [][]string
	for i := 0; i < int(minLen); i++ {
		unequalFields = append(unequalFields, checkFields(
			*chain1[i], *chain2[i], typeOfCert))
	}

	return unequalFields
}

// Compares a certificate to a request. Returns (true, []) if both items
// contain matching data (for the things that can match). Otherwise, returns
// (false, unequalFields) where unequalFields contains the names of all fields
// which did not match.
func certEqualsRequest(cert *x509.Certificate, request csr.CertificateRequest) (bool, []string) {
	equal := true
	var unequalFields []string

	if cert.Subject.CommonName != request.CN {
		equal = false
		unequalFields = append(unequalFields, "Common Name")
	}

	nameData := make(map[string]map[string]bool)
	nameData["Country"] = make(map[string]bool)
	nameData["Organization"] = make(map[string]bool)
	nameData["OrganizationalUnit"] = make(map[string]bool)
	nameData["Locality"] = make(map[string]bool)
	nameData["Province"] = make(map[string]bool)
	for _, name := range request.Names {
		nameData["Country"][name.C] = true
		nameData["Organization"][name.O] = true
		nameData["OrganizationalUnit"][name.OU] = true
		nameData["Locality"][name.L] = true
		nameData["Province"][name.ST] = true
	}
	for _, country := range cert.Subject.Country {
		if _, exists := nameData["Country"][country]; !exists {
			equal = false
			unequalFields = append(unequalFields, "Country")
		}
	}
	for _, organization := range cert.Subject.Organization {
		if _, exists := nameData["Organization"][organization]; !exists {
			equal = false
			unequalFields = append(unequalFields, "Organization")
		}
	}
	for _, organizationalUnit := range cert.Subject.OrganizationalUnit {
		if _, exists := nameData["OrganizationalUnit"][organizationalUnit]; !exists {
			equal = false
			unequalFields = append(unequalFields, "OrganizationalUnit")
		}
	}
	for _, locality := range cert.Subject.Locality {
		if _, exists := nameData["Locality"][locality]; !exists {
			equal = false
			unequalFields = append(unequalFields, "Locality")
		}
	}
	for _, province := range cert.Subject.Province {
		if _, exists := nameData["Province"][province]; !exists {
			equal = false
			unequalFields = append(unequalFields, "Province")
		}
	}

	// TODO: check hosts

	if cert.BasicConstraintsValid && request.CA != nil {
		if cert.MaxPathLen != request.CA.PathLength {
			equal = false
			unequalFields = append(unequalFields, "Max Path Length")
		}
		// TODO: check expiry
	}

	// TODO: check isCA

	return equal, unequalFields
}

// Returns a random element of the input slice.
func randomElement(set []string) string {
	return set[rand.Intn(len(set))]
}

// Just to clean the code up a bit.
func checkError(err error, t *testing.T) {
	if err != nil {
		// t.Fatal is more clean, but a panic gives more information for debugging
		panic(err)
		// t.Fatal(err.Error())
	}
}
