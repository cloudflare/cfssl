package bundler

// This test file contains tests on checking the correctness of BundleFromRemote
import (
	"testing"
)

// remoteTest defines a test case for BundleFromRemote. Hostname and ip are the test inputs.
// bundlerConstructor points the bundler ctor and errorCallback handles the error checking.
type remoteTest struct {
	hostname           string
	ip                 string
	bundlerConstructor func(*testing.T) (b *Bundler)
	errorCallback      func(*testing.T, error)
}

const (
	ValidSSLSite           = "google.com"
	SelfSignedSSLSite      = "cacert.org"
	MismatchedHostnameSite = "golang.org"
	ExpiredCertSite        = "testssl-expire.disig.sk"
	InvalidSite            = "cloudflare1337.com"
	ValidSNI               = "alice.sni.velox.ch"
	ValidSNIWildcard       = "cloudflare.sni.velox.ch"
	ValidSNIIP             = "85.25.46.13"
)

// test cases of BundleFromRemote
var remoteTests = []remoteTest{
	{
		hostname:           ValidSSLSite,
		bundlerConstructor: newBundler,
		errorCallback:      nil,
	},
	{
		hostname:           SelfSignedSSLSite,
		bundlerConstructor: newBundler,
		errorCallback:      ExpectErrorMessages([]string{`"code":1220`, "x509: certificate signed by unknown authority"}),
	},
	{
		hostname:           MismatchedHostnameSite,
		bundlerConstructor: newBundler,
		errorCallback:      ExpectErrorMessages([]string{`"code":1200`, "x509: certificate is valid for"}),
	},
	{
		hostname:           ExpiredCertSite,
		bundlerConstructor: newBundler,
		errorCallback:      ExpectErrorMessages([]string{`"code":1211`, "x509: certificate has expired or is not yet valid"}),
	},
	{
		hostname:           InvalidSite,
		bundlerConstructor: newBundler,
		errorCallback:      ExpectErrorMessages([]string{`"code":6000`, "dial tcp: lookup cloudflare1337.com: no such host"}),
	},
	{
		hostname:           ValidSNI,
		bundlerConstructor: newBundler,
		errorCallback:      nil,
	},
	{
		hostname:           ValidSNIWildcard,
		bundlerConstructor: newBundler,
		errorCallback:      nil,
	},
	{
		hostname:           ValidSNI,
		ip:                 ValidSNIIP,
		bundlerConstructor: newBundler,
		errorCallback:      nil,
	},
	{
		hostname:           ValidSNIWildcard,
		ip:                 ValidSNIIP,
		bundlerConstructor: newBundler,
		errorCallback:      nil,
	},
}

// TestBundleFromRemote goes through the test cases defined in remoteTests and run them through. See below for test case definitions.
func TestBundleFromRemote(t *testing.T) {
	for _, test := range remoteTests {
		b := test.bundlerConstructor(t)
		_, err := b.BundleFromRemote(test.hostname, test.ip)
		if test.errorCallback != nil {
			test.errorCallback(t, err)
		} else {
			if err != nil {
				t.Errorf("expected no error. but an error occurred: %s", err.Error())
			}
		}
	}
}
