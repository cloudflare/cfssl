package bundler

// This test file contains tests on checking Bundle.Status with SHA-1 deprecation warning.
import (
	"io/ioutil"
	"testing"

	"github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
	"github.com/cloudflare/cfssl/ubiquity"
)

const (
	sha1CA           = "testdata/ca.pem"
	sha1Intermediate = "testdata/inter-L1-sha1.pem"
	sha2Intermediate = "testdata/inter-L1.pem"
	intermediateKey  = "testdata/inter-L1.key"
	leafCSR          = "testdata/inter-L2.csr"
)

func TestChromeWarning(t *testing.T) {
	b := newCustomizedBundlerFromFile(t, sha1CA, sha1Intermediate, "")

	s, err := local.NewSignerFromFile(sha1Intermediate, intermediateKey, nil)
	if err != nil {
		t.Fatal(err)
	}

	csrBytes, err := ioutil.ReadFile(leafCSR)
	if err != nil {
		t.Fatal(err)
	}

	signingRequest := signer.SignRequest{Request: string(csrBytes)}

	certBytes, err := s.Sign(signingRequest)
	if err != nil {
		t.Fatal(err)
	}

	// Bundle a leaf cert with default 1 year expiration
	bundle, err := b.BundleFromPEMorDER(certBytes, nil, Ubiquitous, "")
	if err != nil {
		t.Fatal("bundling failed: ", err)
	}

	// should be not ubiquitous due to SHA2 and ECDSA support issues in legacy platforms
	if bundle.Status.Code&errors.BundleNotUbiquitousBit != errors.BundleNotUbiquitousBit {
		t.Fatal("Incorrect bundle status code. Bundle status code:", bundle.Status.Code)
	}

	fullChain := append(bundle.Chain, bundle.Root)
	rejectingPlatforms := ubiquity.DeprecatedSHA1Platforms(fullChain)
	deprecationMessage := deprecateSHA1Warning(rejectingPlatforms)
	if deprecationMessage == "" {
		t.Fatal("SHA1 Deprecation Message should not be empty")
	}
	// check SHA1 deprecation warnings
	foundMsg := false
	for _, message := range bundle.Status.Messages {
		if message == deprecationMessage {
			foundMsg = true
		}
	}
	if !foundMsg {
		t.Fatalf("Incorrect bundle status messages. Bundle status messages:%s, expected: %s\n", bundle.Status.Messages, deprecationMessage)
	}

}
