package bundler

// This test file contains tests on checking the correctness of BundleFromRemote
import (
	"net"
	"strings"
	"testing"

	"github.com/cloudflare/cfssl/ubiquity"
)

// remoteTest defines a test case for BundleFromRemote. Hostname and ip are the test inputs.
// bundlerConstructor points the bundler ctor and errorCallback handles the error checking.
type remoteTest struct {
	hostname           string
	ip                 string
	bundlerConstructor func(*testing.T) (b *Bundler)
	errorCallback      func(*testing.T, *remoteTest, error)
	bundleCallback     func(*testing.T, *remoteTest, *Bundle)
}

const (
	RSACertSite            = "rsa2048.badssl.com"
	SelfSignedSSLSite      = "self-signed.badssl.com"
	MismatchedHostnameSite = "wrong.host.badssl.com"
	ECCCertSite            = "ecc256.badssl.com"
	InvalidSite            = "cloudflare1337.com"
	ValidSNI               = "badssl.com"
	ValidSNIWildcard       = "badssl.com"
	SNISANWildcard         = "*.badssl.com"
	InvalidIP              = "300.300.300.300"
)

func getBundleHostnameChecker(hostname string) func(*testing.T, *remoteTest, *Bundle) {
	return func(t *testing.T, test *remoteTest, bundle *Bundle) {
		if bundle == nil {
			t.Fatalf("Nil bundle returned hostname=%q ip=%q", test.hostname, test.ip)
		}
		var found = false
		for _, h := range bundle.Hostnames {
			if h == hostname {
				found = true
			}
		}
		if !found {
			t.Errorf("hostname expected but not found: %s hostname=%q ip=%q found=%v", hostname, test.hostname, test.ip, bundle.Hostnames)
		}
	}
}

func expectErrorMessages(expectedContents []string) func(*testing.T, *remoteTest, error) {
	return func(t *testing.T, test *remoteTest, err error) {
		if err == nil {
			t.Fatalf("Expected error has %s. Got nothing. hostname=%q ip=%q", expectedContents, test.hostname, test.ip)
		} else {
			for _, expected := range expectedContents {
				if !strings.Contains(err.Error(), expected) {
					t.Fatalf("Expected error has %s. Got %s. hostname=%q ip=%q", expected, err.Error(), test.hostname, test.ip)
				}
			}
		}
	}
}

// test cases of BundleFromRemote
var remoteTests = []remoteTest{
	{
		hostname:           RSACertSite,
		bundlerConstructor: newBundler,
		errorCallback:      nil,
	},
	{
		hostname:           ECCCertSite,
		bundlerConstructor: newBundler,
		errorCallback:      nil,
	},
	{
		hostname:           SelfSignedSSLSite,
		bundlerConstructor: newBundler,
		errorCallback:      expectErrorMessages([]string{`"code":12`}), // only check it is a 12xx error
	},
	{
		hostname:           MismatchedHostnameSite,
		bundlerConstructor: newBundler,
		errorCallback:      expectErrorMessages([]string{`"code":12`}), // only check it is a 12xx error
	},
	{
		hostname:           InvalidSite,
		bundlerConstructor: newBundler,
		errorCallback:      expectErrorMessages([]string{`"code":6000`, "dial tcp: lookup cloudflare1337.com"}),
	},
	{
		hostname:           InvalidIP,
		bundlerConstructor: newBundler,
		errorCallback:      expectErrorMessages([]string{`"code":6000`, "dial tcp: lookup 300.300.300.300"}),
	},
	{
		ip:                 InvalidIP,
		bundlerConstructor: newBundler,
		errorCallback:      expectErrorMessages([]string{`"code":6000`, "dial tcp: lookup 300.300.300.300"}),
	},
}

// TestBundleFromRemote goes through the test cases defined in remoteTests and run them through. See above for test case definitions.
func TestBundleFromRemote(t *testing.T) {
	t.Skip("expired cert https://github.com/cloudflare/cfssl/issues/1237")
	for _, bf := range []BundleFlavor{Ubiquitous, Optimal} {
		for _, test := range remoteTests {
			b := test.bundlerConstructor(t)
			bundle, err := b.BundleFromRemote(test.hostname, test.ip, bf)
			if test.errorCallback != nil {
				test.errorCallback(t, &test, err)
			} else {
				if err != nil {
					t.Fatalf("expected no error. but an error occurred hostname=%q ip=%q errpr=%q", test.hostname, test.ip, err.Error())
				}
				if test.bundleCallback != nil {
					test.bundleCallback(t, &test, bundle)
				}
			}
		}
	}
}

func resolveHostIP(host string) string {
	addrs, err := net.LookupHost(host)
	if err != nil {
		panic(err)
	}
	if len(addrs) == 0 {
		panic("failed to resolve " + host)
	}
	return addrs[0]
}

var remoteSNITests = []remoteTest{
	{
		hostname:           ValidSNI,
		bundlerConstructor: newBundler,
		errorCallback:      nil,
		bundleCallback:     getBundleHostnameChecker(ValidSNI),
	},
	{
		hostname:           ValidSNIWildcard,
		bundlerConstructor: newBundler,
		errorCallback:      nil,
		bundleCallback:     getBundleHostnameChecker(SNISANWildcard),
	},
	{
		hostname:           ValidSNI,
		ip:                 resolveHostIP(ValidSNI),
		bundlerConstructor: newBundler,
		errorCallback:      nil,
		bundleCallback:     getBundleHostnameChecker(ValidSNI),
	},
	{
		hostname:           ValidSNIWildcard,
		ip:                 resolveHostIP(ValidSNIWildcard),
		bundlerConstructor: newBundler,
		errorCallback:      nil,
		bundleCallback:     getBundleHostnameChecker(SNISANWildcard),
	},
}

// TestBundleFromRemoteSNI goes through the test cases defined in remoteSNITests and run them through. See above for test case definitions.
func TestBundleFromRemoteSNI(t *testing.T) {
	t.Skip("expired cert https://github.com/cloudflare/cfssl/issues/1237")
	for _, bf := range []BundleFlavor{Ubiquitous, Optimal} {
		for _, test := range remoteSNITests {
			b := test.bundlerConstructor(t)
			bundle, err := b.BundleFromRemote(test.hostname, test.ip, bf)
			if test.errorCallback != nil {
				test.errorCallback(t, &test, err)
			} else {
				if err != nil {
					t.Errorf("expected no error. but an error occurred: %s", err.Error())
				}
				if test.bundleCallback != nil {
					test.bundleCallback(t, &test, bundle)
				}
			}
		}
	}
}

func TestBundleFromRemoteFlavor(t *testing.T) {
	// This test was crafted for the specific cert bundle that benflare.us was
	// serving. The majority of the functionality is validated via the other
	// bundle tests.
	t.Skip("skipped; need new example site for test")

	b := newBundler(t)
	ubiquity.Platforms = nil
	ubiquity.LoadPlatforms(testMetadata)

	bundle, err := b.BundleFromRemote(ECCCertSite, "", Ubiquitous)
	if err != nil {
		t.Fatalf("expected no error. but an error occurred: %s", err.Error())
	}
	if len(bundle.Chain) != 3 {
		t.Error("expected 3-cert bundle. Got ", len(bundle.Chain))
	}
	if len(bundle.Status.Untrusted) != 0 {
		t.Error("expected no untrusted platforms. Got ", bundle.Status.Untrusted)
	}

	bundle, err = b.BundleFromRemote(ECCCertSite, "", Optimal)
	if err != nil {
		t.Errorf("expected no error. but an error occurred: %s", err.Error())
	}
	if len(bundle.Chain) != 2 {
		t.Error("expected 2-cert bundle. Got ", len(bundle.Chain))
	}

}
