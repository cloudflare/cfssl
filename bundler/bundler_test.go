package bundler

// This test file contains mostly tests on checking Bundle.Status when bundling under different circumstances.
import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"io/ioutil"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/ubiquity"
)

const (
	testCaBundle        = "testdata/ca-bundle.pem"
	testIntCaBundle     = "testdata/int-bundle.pem"
	testNSSRootBundle   = "testdata/nss.pem"
	testMetadata        = "testdata/ca-bundle.crt.metadata"
	sgizmoPEM           = "testdata/sgizmo.pem"
	draftkingsPEM       = "testdata/draftkings.pem"
	lazadaPEM           = "testdata/lazada.pem"
	riotPEM             = "testdata/riot.pem"
	testCFSSLRootBundle = "testdata/ca.pem"
	testCAFile          = "testdata/ca.pem"
	testCAKeyFile       = "testdata/ca.key"
	testCFSSLIntBundle  = "testdata/intermediates.crt"
	emptyPEM            = "testdata/empty.pem"
)

// Simply create a bundler
func TestNewBundler(t *testing.T) {
	newBundler(t)
}

// JSON object of a bundle
type bundleObject struct {
	Bundle      string   `json:"bundle"`
	Cert        string   `json:"crt"`
	Key         string   `json:"key"`
	KeyType     string   `json:"key_type"`
	KeySize     int      `json:"key_size"`
	Issuer      string   `json:"issuer"`
	Subject     string   `json:"subject"`
	Expires     string   `json:"expires"`
	Hostnames   []string `json:"hostnames"`
	OCSPSupport bool     `json:"ocsp_support"`
	CRLSupport  bool     `json:"crl_support"`
	OCSP        []string `json:"ocsp"`
	Signature   string   `json:"signature"`
	Status      BundleStatus
}

var godaddyIssuerString = `/Country=US/Organization=The Go Daddy Group, Inc./OrganizationalUnit=Go Daddy Class 2 Certification Authority`
var godaddySubjectString = `/Country=US/Province=Arizona/Locality=Scottsdale/Organization=GoDaddy.com, Inc./OrganizationalUnit=http://certificates.godaddy.com/repository/CommonName=Go Daddy Secure Certification Authority/SerialNumber=07969287`

// Test marshal to JSON
// Also serves as a JSON format regression test.
func TestBundleMarshalJSON(t *testing.T) {
	b := newBundler(t)
	bundle, _ := b.BundleFromPEM(validRootCert, nil, Optimal)
	bytes, err := json.Marshal(bundle)

	if err != nil {
		t.Fatal(err)
	}

	var obj bundleObject
	err = json.Unmarshal(bytes, &obj)
	if err != nil {
		t.Fatal(err)
	}

	if obj.Bundle == "" {
		t.Fatal("bundle is empty.")
	}
	if obj.Bundle != string(validRootCert) {
		t.Fatal("bundle is incorrect:", obj.Bundle)
	}

	if obj.Key != "" {
		t.Fatal("key is not empty:", obj.Key)
	}

	if obj.Cert != string(validRootCert) {
		t.Fatal("Cert is not recovered")
	}

	if obj.KeyType != "2048-bit RSA" {
		t.Fatal("Incorrect key type:", obj.KeyType)
	}

	if obj.KeySize != 2048 {
		t.Fatal("Incorrect key size:", obj.KeySize)
	}

	if obj.Issuer != godaddyIssuerString {
		t.Fatal("Incorrect issuer:", obj.Issuer)
	}

	if obj.Subject != godaddySubjectString {
		t.Fatal("Incorrect subject:", obj.Subject)
	}

	if obj.Expires != "2026-11-16T01:54:37Z" {
		t.Fatal("Incorrect expiration time:", obj.Expires)
	}

	if len(obj.Hostnames) != 1 || obj.Hostnames[0] != "Go Daddy Secure Certification Authority" {
		t.Fatal("Incorrect hostnames:", obj.Hostnames)
	}

	if obj.OCSPSupport != true {
		t.Fatal("Incorrect OCSP support flag:", obj.OCSPSupport)
	}

	if obj.CRLSupport != true {
		t.Fatal("Incorrect CRL support flag:", obj.CRLSupport)
	}

	if len(obj.OCSP) != 1 || obj.OCSP[0] != `http://ocsp.godaddy.com` {
		t.Fatal("Incorrect ocsp server list:", obj.OCSP)
	}

	if obj.Signature != "SHA1WithRSA" {
		t.Fatal("Incorrect cert signature method:", obj.Signature)
	}
}

func TestBundleNonKeylessMarshalJSON(t *testing.T) {
	b := newCustomizedBundlerFromFile(t, testCFSSLRootBundle, testCFSSLIntBundle, "")
	bundle, _ := b.BundleFromFile(leafECDSA256, leafKeyECDSA256, Optimal)
	jsonBytes, err := json.Marshal(bundle)

	if err != nil {
		t.Fatal(err)
	}

	var obj map[string]interface{}
	err = json.Unmarshal(jsonBytes, &obj)
	if err != nil {
		t.Fatal(err)
	}

	key := obj["key"].(string)
	keyBytes, _ := ioutil.ReadFile(leafKeyECDSA256)
	keyBytes = bytes.Trim(keyBytes, " \n")
	if key != string(keyBytes) {
		t.Fatal("key is not recovered.")
	}

	cert := obj["crt"].(string)
	certBytes, _ := ioutil.ReadFile(leafECDSA256)
	certBytes = bytes.Trim(certBytes, " \n")
	if cert != string(certBytes) {
		t.Fatal("cert is not recovered.")
	}

	keyType := obj["key_type"]
	if keyType != "256-bit ECDSA" {
		t.Fatal("Incorrect key type:", keyType)
	}

}

// Test marshal to JSON on hostnames
func TestBundleHostnamesMarshalJSON(t *testing.T) {
	b := newBundler(t)
	bundle, _ := b.BundleFromRemote("cloudflare.com", "")
	hostnames, _ := json.Marshal(bundle.Hostnames)
	expectedOne := []byte(`["www.cloudflare.com","cloudflare.com"]`)
	expectedTheOther := []byte(`["cloudflare.com","www.cloudflare.com"]`)
	if !bytes.Equal(hostnames, expectedOne) && !bytes.Equal(hostnames, expectedTheOther) {
		t.Fatal("Hostnames construction failed for cloudflare.com.")
	}

	bundle, _ = b.BundleFromPEM(validRootCert, nil, Optimal)
	expected := []byte(`["Go Daddy Secure Certification Authority"]`)
	hostnames, _ = json.Marshal(bundle.Hostnames)
	if !bytes.Equal(hostnames, expected) {
		t.Fatal("Hostnames construction failed for godaddy root cert.", string(hostnames))
	}

}

// Tests on verifying the rebundle flag and error code in Bundle.Status when rebundling.
func TestRebundleFromPEM(t *testing.T) {
	newBundler := newCustomizedBundlerFromFile(t, testCFSSLRootBundle, interL1, "")
	newBundle, err := newBundler.BundleFromPEM(expiredBundlePEM, nil, Optimal)
	if err != nil {
		t.Fatalf("Re-bundle failed. %s", err.Error())
	}
	newChain := newBundle.Chain

	if len(newChain) != 2 {
		t.Fatalf("Expected bundle chain length is 2. Got %d.", len(newChain))
	}

	expiredChain, _ := helpers.ParseCertificatesPEM(expiredBundlePEM)
	for i, cert := range newChain {
		old := expiredChain[i]
		if i == 0 {
			if !bytes.Equal(old.Signature, cert.Signature) {
				t.Fatal("Leaf cert should be the same.")
			}
		} else {
			if bytes.Equal(old.Signature, cert.Signature) {
				t.Fatal("Intermediate cert should be different.")
			}
		}
	}
	// The status must be {Code: ExpiringBit is not set, IsRebundled:true, ExpiringSKIs:{}}
	if len(newBundle.Status.ExpiringSKIs) != 0 || !newBundle.Status.IsRebundled || newBundle.Status.Code&errors.BundleExpiringBit != 0 {
		t.Fatal("Rebundle Status is incorrect.")
	}

}

func TestRebundleExpiring(t *testing.T) {
	// make a policy that generate a cert expires in one hour.
	expiry := 1 * time.Hour
	policy := &config.Signing{
		Profiles: map[string]*config.SigningProfile{
			"expireIn1Hour": &config.SigningProfile{
				Usage:  []string{"cert sign"},
				Expiry: expiry,
				CA:     true,
			},
		},
		Default: config.DefaultConfig(),
	}
	// Generate a intermediate cert that expires in one hour.
	expiringPEM := createInterCert(t, interL1CSR, policy, "expireIn1Hour")
	rootBundlePEM, _ := ioutil.ReadFile(testCFSSLRootBundle)

	// Use the expiring intermediate to initiate a bundler.
	bundler, err := NewBundlerFromPEM(rootBundlePEM, expiringPEM)
	newBundle, err := bundler.BundleFromPEM(expiredBundlePEM, nil, Optimal)
	if err != nil {
		t.Fatalf("Re-bundle failed. %s", err.Error())
	}
	// Check the bundle content.
	newChain := newBundle.Chain
	if len(newChain) != 2 {
		t.Fatalf("Expected bundle chain length is 2. Got %d.", len(newChain))
	}
	// The status must be {Code: ExpiringBit is set, IsRebundled:true, ExpiringSKIs:{"D75D4829692C0EF473AB401C46A8E392147B0710"}}
	if len(newBundle.Status.ExpiringSKIs) != 1 || !newBundle.Status.IsRebundled || newBundle.Status.Code&errors.BundleExpiringBit == 0 {
		t.Fatal("Rebundle Status is incorrect.")
	}
	expectedSKI := "D75D4829692C0EF473AB401C46A8E392147B0710"
	if newBundle.Status.ExpiringSKIs[0] != expectedSKI {
		t.Fatalf("Expected expiring cert SKI is %s, got %s\n", expectedSKI, newBundle.Status.ExpiringSKIs[0])
	}

}

// Test on verifying ubiquitous messaging in Bundle.Status.
func TestUbiquitousBundle(t *testing.T) {
	L1Cert := readCert(interL1)
	// Simulate the case that L1Cert is added to trust store by one platform but not yet in another.
	b := newCustomizedBundlerFromFile(t, testCFSSLRootBundle, testCFSSLIntBundle, "")
	b.RootPool.AddCert(L1Cert)
	// Prepare Platforms.
	platformA := ubiquity.Platform{Name: "MacroSoft", Weight: 100, HashAlgo: "SHA2", KeyAlgo: "ECDSA256", KeyStoreFile: testCFSSLRootBundle}
	platformA.ParseAndLoad()
	platformB := ubiquity.Platform{Name: "Godzilla", Weight: 100, HashAlgo: "SHA2", KeyAlgo: "ECDSA256", KeyStoreFile: testCFSSLRootBundle}
	platformB.ParseAndLoad()
	platformA.KeyStore.Add(L1Cert)
	ubiquity.Platforms = append([]ubiquity.Platform{}, platformA, platformB)

	// Optimal bundle algorithm will picks up the new root and shorten the chain.
	optimalBundle, err := b.BundleFromFile(leafECDSA256, "", Optimal)
	if err != nil {
		t.Fatal("Optimal bundle failed:", err)
	}
	if len(optimalBundle.Chain) != 2 {
		t.Fatal("Optimal bundle failed the chain length test. Chain length:", len(optimalBundle.Chain))
	}
	// The only trust platform is "Macrosoft".
	if len(optimalBundle.Status.Untrusted) != 1 {
		t.Fatal("Optimal bundle status has incorrect untrusted platforms")
	}
	checkUbiquityWarningAndCode(t, optimalBundle, true)

	// Ubiquitous bundle will remain the same.
	ubiquitousBundle, err := b.BundleFromFile(leafECDSA256, "", Ubiquitous)
	if err != nil {
		t.Fatal("Ubiquitous bundle failed")

	}
	if len(ubiquitousBundle.Chain) != 3 {
		t.Fatal("Ubiquitous bundle failed")
	}
	// Should be trusted by both platforms.
	if len(ubiquitousBundle.Status.Untrusted) != 0 {
		t.Fatal("Ubiquitous bundle status has incorrect untrusted platforms", len(ubiquitousBundle.Status.Untrusted))
	}
	checkUbiquityWarningAndCode(t, ubiquitousBundle, false)
}

func checkUbiquityWarningAndCode(t *testing.T, bundle *Bundle, expected bool) {
	found := false
	for _, msg := range bundle.Status.Messages {
		if strings.Contains(msg, untrustedWarningStub) {
			found = true
		}
	}
	if found != expected {
		t.Fatal("Expected ubiquity warning: ", expected, " Found ubiquity warning:", found)
	}

	// check status code
	if (expected && bundle.Status.Code&errors.BundleNotUbiquitousBit == 0) ||
		(!expected && bundle.Status.Code&errors.BundleNotUbiquitousBit == 1) {
		t.Fatal("Bundle status code is incorrect:", bundle.Status.Code)
	}
}

// Regression test on ubiquity.
// It is to make sure ubiquitous bundles are generated so they can be trusted by Android 2.2
// and its variants.
//
// Leaf certs from SurveyGizmo.com and DraftKings.com are issued by a GoDaddy intermediate cert,
// which in turn is issued by a GoDaddy Root Certificate (CN: Go Daddy Root Certificate Authority
// G2). The NSS library includes this root cert. So optimal bundle should only have two certs.
// However,  that root cert is not present in trust stores of Android <= 2.2. Ubiquitous bundling
// should be able to recognize this scenario and produces a bundle that includes the GoDaddy Root
// cert as an intermediate, which is verified by older trust roots.
// Also, lazada.com.ph (mentioned in CFSSL-48) is having a similar problem with GeoTrust CA.
func TestAndroidUbiquitousBundle(t *testing.T) {
	leafs := []string{sgizmoPEM, draftkingsPEM, lazadaPEM}
	for _, leaf := range leafs {
		b := newCustomizedBundlerFromFile(t, testNSSRootBundle, testIntCaBundle, "")
		ubiquity.Platforms = nil
		ubiquity.LoadPlatforms(testMetadata)

		// Optimal bundle algorithm will use the Godaddy Root/GeoTrust CA.
		optimalBundle, err := b.BundleFromFile(leaf, "", Optimal)
		if err != nil {
			t.Fatal("Optimal bundle failed:", err)
		}
		if len(optimalBundle.Chain) != 2 {
			t.Fatal("Optimal bundle failed")
		}
		checkUbiquityWarningAndCode(t, optimalBundle, true)

		// Ubiquitous bundle will include a 2nd intermediate CA.
		ubiquitousBundle, err := b.BundleFromFile(leaf, "", Ubiquitous)
		if err != nil {
			t.Fatal("Ubiquitous bundle failed")

		}
		if len(ubiquitousBundle.Chain) != 3 {
			t.Fatal("Ubiquitous bundle failed")
		}
		if len(ubiquitousBundle.Status.Untrusted) != 0 {
			t.Fatal("Regression: Ubiquitous bundle has untrusted platforms: ", ubiquitousBundle.Status.Untrusted)
		}
		checkUbiquityWarningAndCode(t, ubiquitousBundle, false)
	}
}

func checkSHA2WarningAndCode(t *testing.T, bundle *Bundle, expected bool) {
	found := false
	for _, msg := range bundle.Status.Messages {
		if strings.Contains(msg, sha2Warning) {
			found = true
		}
	}
	if found != expected {
		t.Fatal("Expected ubiquity warning: ", expected, " Found ubiquity warning:", found)
	}
	// check status code
	if bundle.Status.Code&errors.BundleNotUbiquitousBit == 0 {
		t.Fatal("Bundle status code is incorrect:", bundle.Status.Code)
	}
}

// Regression test on SHA-2 Warning
// Riot Games once bundle a cert issued by DigiCert SHA2 High Assurance Server CA. The resulting
// bundle uses SHA-256 which is not supported in Windows XP SP2. We should present a warning
// on this.
func TestSHA2Warning(t *testing.T) {
	b := newCustomizedBundlerFromFile(t, testNSSRootBundle, testIntCaBundle, "")
	// Optimal bundle algorithm will use the Godaddy Root/GeoTrust CA.
	optimalBundle, err := b.BundleFromFile(riotPEM, "", Optimal)
	if err != nil {
		t.Fatal("Optimal bundle failed:", err)
	}
	checkSHA2WarningAndCode(t, optimalBundle, true)

	// Ubiquitous bundle will include a 2nd intermediate CA.
	ubiquitousBundle, err := b.BundleFromFile(riotPEM, "", Ubiquitous)
	if err != nil {
		t.Fatal("Ubiquitous bundle failed")

	}
	checkSHA2WarningAndCode(t, ubiquitousBundle, true)
}

// === Helper function block ===

// readCert read a PEM file and returns a cert.
func readCert(filename string) *x509.Certificate {
	bytes, _ := ioutil.ReadFile(filename)
	cert, _ := helpers.ParseCertificatePEM(bytes)
	return cert
}

// newBundler is a helper function that returns a new Bundler. If it fails to do so,
// it fails the test suite immediately.
func newBundler(t *testing.T) (b *Bundler) {
	b, err := NewBundler(testCaBundle, testIntCaBundle)
	if err != nil {
		t.Fatal(err)
	}
	return
}

// create a test intermediate cert in PEM
func createInterCert(t *testing.T, csrFile string, policy *config.Signing, profileName string) (certPEM []byte) {
	signer, err := signer.NewSigner(testCAFile, testCAKeyFile, policy)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := ioutil.ReadFile(csrFile)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err = signer.Sign("cloudflare-inter.com", csr, profileName)
	if err != nil {
		t.Fatal(err)
	}
	return

}
func newBundlerFromPEM(t *testing.T, caBundlePEM, intBundlePEM []byte) (b *Bundler) {
	b, err := NewBundlerFromPEM(caBundlePEM, intBundlePEM)
	if err != nil {
		t.Fatal(err)
	}
	return
}

// newCustomizedBundleCreator is a helper function that returns a new Bundler
// takes specified CA bundle, intermediate bundle, and any additional intermdiate certs  to generate a bundler.
func newCustomizedBundlerFromFile(t *testing.T, caBundle, intBundle, adhocInters string) (b *Bundler) {
	b, err := NewBundler(caBundle, intBundle)
	if err != nil {
		t.Fatal(err)
	}
	if adhocInters != "" {
		moreIntersPEM, err := ioutil.ReadFile(adhocInters)
		if err != nil {
			t.Fatalf("Read additional intermediates failed. %v",
				err)
		}
		intermediates, err := helpers.ParseCertificatesPEM(moreIntersPEM)
		if err != nil {
			t.Fatalf("Parsing additional intermediates failed. %s", err.Error())
		}
		for _, c := range intermediates {
			b.IntermediatePool.AddCert(c)
		}

	}
	return

}

// newBundlerWithoutInters is a helper function that returns a bundler with an empty
// intermediate cert pool. Such bundlers can help testing error handling in cert
// bundling.
func newBundlerWithoutInters(t *testing.T) (b *Bundler) {
	b = newBundler(t)
	// Re-assign an empty intermediate cert pool
	b.IntermediatePool = x509.NewCertPool()
	return
}

// newBundlerWithoutRoots is a helper function that returns a bundler with an empty
// root cert pool. Such bundlers can help testing error handling in cert
// bundling.
func newBundlerWithoutRoots(t *testing.T) (b *Bundler) {
	b = newBundler(t)
	// Re-assign an empty root cert pool
	b.RootPool = x509.NewCertPool()
	return
}

// A helper function that returns a errorCallback function which expects certain error content in
// an error message.
func ExpectErrorMessage(expectedErrorContent string) func(*testing.T, error) {
	return func(t *testing.T, err error) {
		if err == nil {
			t.Fatalf("Expected error has %s. Got nothing.", expectedErrorContent)
		} else if !strings.Contains(err.Error(), expectedErrorContent) {
			t.Fatalf("Expected error has %s. Got %s", expectedErrorContent, err.Error())
		}
	}
}

// A helper function that returns a errorCallback function which inspect error message for
// all expected messages.
func ExpectErrorMessages(expectedContents []string) func(*testing.T, error) {
	return func(t *testing.T, err error) {
		if err == nil {
			t.Fatalf("Expected error has %s. Got nothing.", expectedContents)
		} else {
			for _, expected := range expectedContents {
				if !strings.Contains(err.Error(), expected) {
					t.Fatalf("Expected error has %s. Got %s", expected, err.Error())
				}
			}
		}
	}
}

// A helper function that returns a bundle chain length checking function
func ExpectBundleLength(expectedLen int) func(*testing.T, *Bundle) {
	return func(t *testing.T, bundle *Bundle) {
		if bundle == nil {
			t.Fatalf("Cert bundle should have a chain of length %d. Got nil.",
				expectedLen)
		} else if len(bundle.Chain) != expectedLen {
			t.Fatalf("Cert bundle should have a chain of length %d. Got chain length %d.",
				expectedLen, len(bundle.Chain))
		}
	}
}
