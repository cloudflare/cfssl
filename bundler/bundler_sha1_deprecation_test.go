package bundler

// This test file contains tests on checking Bundle.Status with SHA-1 deprecation warning.
import (
	"testing"

	"github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/ubiquity"
)

const (
	sha1CA                = "testdata/ca.pem"
	testChromeMetadata    = "testdata/ca.pem.metadata"
	sha1Intermediate      = "testdata/inter-L1-sha1.pem"
	sha2LeafExp2015Jun2nd = "testdata/inter-L2-1.pem"
	sha2LeafExp2016Jan2nd = "testdata/inter-L2-2.pem"
	sha2LeafExp2016Jun2nd = "testdata/inter-L2-3.pem"
	sha2LeafExp2017Jan2nd = "testdata/inter-L2-4.pem"
)

func TestChromeWarning(t *testing.T) {
	b := newCustomizedBundlerFromFile(t, sha1CA, sha1Intermediate, "")
	// The metadata contains Chrome M39, M40 and M41. The effective date for their SHA1 deprecation
	// is pushed to 2014-09-01 to enable unit testing.
	ubiquity.LoadPlatforms(testChromeMetadata)

	// Bundle a leaf cert with expiration on 2015-06-02.
	// Expect no SHA-1 deprecation warnings but a SHA2 warning.
	bundle, err := b.BundleFromFile(sha2LeafExp2015Jun2nd, "", Ubiquitous)
	if err != nil {
		t.Fatal("bundling failed: ", err)
	}
	if bundle.Status.Code|errors.BundleNotUbiquitousBit != errors.BundleNotUbiquitousBit {
		t.Fatal("Incorrect bundle status code. Bundle status:", bundle.Status)
	}

	if len(bundle.Status.Messages) != 1 || bundle.Status.Messages[0] != sha2Warning {
		t.Fatal("Incorrect bundle status messages. Bundle status messages:", bundle.Status.Messages)
	}

	// Bundle a leaf cert with expiration on 2016-01-02.
	// Expect one SHA-1 deprecation warning from Chrome M41 and a SHA2 warning.
	bundle, err = b.BundleFromFile(sha2LeafExp2016Jan2nd, "", Ubiquitous)
	if err != nil {
		t.Fatal("bundling failed: ", err)
	}
	if bundle.Status.Code|errors.BundleNotUbiquitousBit != errors.BundleNotUbiquitousBit {
		t.Fatal("Incorrect bundle status code. Bundle status:", bundle.Status)
	}

	if len(bundle.Status.Messages) != 2 || bundle.Status.Messages[0] != sha2Warning ||
		bundle.Status.Messages[1] != deprecateSHA1WarningStub+" Chrome Browser M41." {
		t.Fatal("Incorrect bundle status messages. Bundle status messages:", bundle.Status.Messages)
	}

	// Bundle a leaf cert with expiration on 2016-06-02.
	// Expect SHA-1 deprecation warnings from Chrome M40, M41 and a SHA2 warning.
	bundle, err = b.BundleFromFile(sha2LeafExp2016Jun2nd, "", Ubiquitous)
	if err != nil {
		t.Fatal("bundling failed: ", err)
	}
	if bundle.Status.Code|errors.BundleNotUbiquitousBit != errors.BundleNotUbiquitousBit {
		t.Fatal("Incorrect bundle status code. Bundle status:", bundle.Status)
	}

	if len(bundle.Status.Messages) != 2 || bundle.Status.Messages[0] != sha2Warning ||
		bundle.Status.Messages[1] != deprecateSHA1WarningStub+" Chrome Browser M40, Chrome Browser M41." {
		t.Fatal("Incorrect bundle status messages. Bundle status messages:", bundle.Status.Messages)
	}

	// Bundle a leaf cert with expiration on 2017-01-02.
	// Expect SHA-1 deprecation warnings from Chrome M39, M40, M41 and a SHA2 warning.
	bundle, err = b.BundleFromFile(sha2LeafExp2017Jan2nd, "", Ubiquitous)
	if err != nil {
		t.Fatal("bundling failed: ", err)
	}
	if bundle.Status.Code|errors.BundleNotUbiquitousBit != errors.BundleNotUbiquitousBit {
		t.Fatal("Incorrect bundle status code. Bundle status:", bundle.Status)
	}

	if len(bundle.Status.Messages) != 2 || bundle.Status.Messages[0] != sha2Warning ||
		bundle.Status.Messages[1] != deprecateSHA1WarningStub+" Chrome Browser M39, Chrome Browser M40, Chrome Browser M41." {
		t.Fatal("Incorrect bundle status messages. Bundle status messages:", bundle.Status.Messages)
	}
}
