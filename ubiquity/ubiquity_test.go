package ubiquity

import (
	"crypto/x509"
	"io/ioutil"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/helpers"
)

const (
	rsa1024  = "testdata/rsa1024sha1.pem"
	rsa2048  = "testdata/rsa2048sha2.pem"
	rsa3072  = "testdata/rsa3072sha2.pem"
	rsa4096  = "testdata/rsa4096sha2.pem"
	ecdsa256 = "testdata/ecdsa256sha2.pem"
	ecdsa384 = "testdata/ecdsa384sha2.pem"
	ecdsa521 = "testdata/ecdsa521sha2.pem"
)

var rsa1024Cert, rsa2048Cert, rsa3072Cert, rsa4096Cert, ecdsa256Cert, ecdsa384Cert, ecdsa521Cert *x509.Certificate

func readCert(filename string) *x509.Certificate {
	bytes, _ := ioutil.ReadFile(filename)
	cert, _ := helpers.ParseCertificatePEM(bytes)
	return cert
}
func init() {
	rsa1024Cert = readCert(rsa1024)
	rsa2048Cert = readCert(rsa2048)
	rsa3072Cert = readCert(rsa3072)
	rsa4096Cert = readCert(rsa4096)
	ecdsa256Cert = readCert(ecdsa256)
	ecdsa384Cert = readCert(ecdsa384)
	ecdsa521Cert = readCert(ecdsa521)

}

func TestCertHashPriority(t *testing.T) {
	if hashPriority(rsa1024Cert) > hashPriority(rsa2048Cert) {
		t.Fatal("Incorrect hash priority")
	}
	if hashPriority(rsa2048Cert) > hashPriority(rsa3072Cert) {
		t.Fatal("Incorrect hash priority")
	}
	if hashPriority(rsa3072Cert) > hashPriority(rsa4096Cert) {
		t.Fatal("Incorrect hash priority")
	}
	if hashPriority(rsa4096Cert) > hashPriority(ecdsa256Cert) {
		t.Fatal("Incorrect hash priority")
	}
	if hashPriority(ecdsa256Cert) > hashPriority(ecdsa384Cert) {
		t.Fatal("Incorrect hash priority")
	}
	if hashPriority(ecdsa384Cert) > hashPriority(ecdsa256Cert) {
		t.Fatal("Incorrect hash priority")
	}
}

func TestCertKeyAlgoPriority(t *testing.T) {
	if keyAlgoPriority(rsa2048Cert) > keyAlgoPriority(rsa3072Cert) {
		t.Fatal("Incorrect hash priority")
	}
	if keyAlgoPriority(rsa3072Cert) > keyAlgoPriority(rsa4096Cert) {
		t.Fatal("Incorrect hash priority")
	}
	if keyAlgoPriority(rsa4096Cert) > keyAlgoPriority(ecdsa256Cert) {
		t.Fatal("Incorrect hash priority")
	}
	if keyAlgoPriority(ecdsa256Cert) > keyAlgoPriority(ecdsa384Cert) {
		t.Fatal("Incorrect hash priority")
	}
	if keyAlgoPriority(ecdsa384Cert) > keyAlgoPriority(ecdsa521Cert) {
		t.Fatal("Incorrect hash priority")
	}
}
func TestChainHashPriority(t *testing.T) {
	var chain []*x509.Certificate
	var p int
	chain = []*x509.Certificate{rsa2048Cert, rsa3072Cert}
	p = HashPriority(chain)
	if p != (hashPriority(rsa2048Cert)+hashPriority(rsa3072Cert))/2 {
		t.Fatal("Incorrect chain hash priority")
	}
}

func TestChainKeyAlgoPriority(t *testing.T) {
	var chain []*x509.Certificate
	var p int
	chain = []*x509.Certificate{rsa2048Cert, rsa3072Cert}
	p = KeyAlgoPriority(chain)
	if p != (keyAlgoPriority(rsa2048Cert)+keyAlgoPriority(rsa3072Cert))/2 {
		t.Fatal("Incorrect chain hash priority")
	}
}
func TestCertHashUbiquity(t *testing.T) {
	if hashUbiquity(rsa2048Cert) != SHA2Ubiquity {
		t.Fatal("incorrect hash ubiquity")
	}
	if hashUbiquity(rsa3072Cert) != SHA2Ubiquity {
		t.Fatal("incorrect hash ubiquity")
	}
	if hashUbiquity(rsa4096Cert) != SHA2Ubiquity {
		t.Fatal("incorrect hash ubiquity")
	}
	if hashUbiquity(rsa2048Cert) < hashUbiquity(rsa3072Cert) {
		t.Fatal("incorrect hash ubiquity")
	}
	if hashUbiquity(rsa3072Cert) < hashUbiquity(rsa4096Cert) {
		t.Fatal("Incorrect hash ubiquity")
	}
	if hashUbiquity(rsa4096Cert) < hashUbiquity(ecdsa256Cert) {
		t.Fatal("Incorrect hash ubiquity")
	}
	if hashUbiquity(ecdsa256Cert) < hashUbiquity(ecdsa384Cert) {
		t.Fatal("Incorrect hash ubiquity")
	}
	if hashUbiquity(ecdsa384Cert) < hashUbiquity(ecdsa256Cert) {
		t.Fatal("Incorrect hash ubiquity")
	}
}

func TestCertKeyAlgoUbiquity(t *testing.T) {
	if keyAlgoUbiquity(rsa2048Cert) != RSAUbiquity {
		t.Fatal("incorrect hash ubiquity")
	}
	if keyAlgoUbiquity(rsa3072Cert) != RSAUbiquity {
		t.Fatal("incorrect hash ubiquity")
	}
	if keyAlgoUbiquity(rsa4096Cert) != RSAUbiquity {
		t.Fatal("incorrect hash ubiquity")
	}
	if keyAlgoUbiquity(ecdsa256Cert) != ECDSA256Ubiquity {
		t.Fatal("incorrect hash ubiquity")
	}
	if keyAlgoUbiquity(ecdsa384Cert) != ECDSA384Ubiquity {
		t.Fatal("incorrect hash ubiquity")
	}
	if keyAlgoUbiquity(ecdsa521Cert) != ECDSA521Ubiquity {
		t.Fatal("incorrect hash ubiquity")
	}
	if keyAlgoUbiquity(rsa2048Cert) < keyAlgoUbiquity(rsa3072Cert) {
		t.Fatal("incorrect hash ubiquity")
	}
	if keyAlgoUbiquity(rsa3072Cert) < keyAlgoUbiquity(rsa4096Cert) {
		t.Fatal("Incorrect hash ubiquity")
	}
	if keyAlgoUbiquity(rsa4096Cert) < keyAlgoUbiquity(ecdsa256Cert) {
		t.Fatal("Incorrect hash ubiquity")
	}
	if keyAlgoUbiquity(ecdsa256Cert) < keyAlgoUbiquity(ecdsa384Cert) {
		t.Fatal("Incorrect hash ubiquity")
	}
	if keyAlgoUbiquity(ecdsa384Cert) < keyAlgoUbiquity(ecdsa256Cert) {
		t.Fatal("Incorrect hash ubiquity")
	}
}

func TestChainHashUbiquity(t *testing.T) {
	chain := []*x509.Certificate{rsa1024Cert, rsa2048Cert}
	if ChainHashUbiquity(chain) != hashUbiquity(rsa2048Cert) {
		t.Fatal("Incorrect chain hash ubiquity")
	}
}

func TestChainKeyAlgoUbiquity(t *testing.T) {
	chain := []*x509.Certificate{rsa1024Cert, rsa2048Cert}
	if ChainKeyAlgoUbiquity(chain) != keyAlgoUbiquity(rsa2048Cert) {
		t.Fatal("Incorrect chain hash ubiquity")
	}
	chain = []*x509.Certificate{ecdsa256Cert, rsa2048Cert}
	if ChainKeyAlgoUbiquity(chain) != keyAlgoUbiquity(ecdsa256Cert) {
		t.Fatal("Incorrect chain hash ubiquity")
	}

}

func TestPlatformKeyStoreUbiquity(t *testing.T) {
	cert1 := rsa1024Cert
	cert2 := rsa2048Cert
	cert3 := ecdsa256Cert
	// load Platforms with test data
	// "Macrosoft" has all three certs.
	// "Godzilla" has two certs, cert1 and cert2.
	// "Pinapple" has cert1.
	// All platforms support the same crypto suite.
	platformA := Platform{Name: "MacroSoft", Weight: 100, HashAlgo: "SHA2", KeyAlgo: "ECDSA256", KeyStoreFile: "testdata/macrosoft.pem"}
	platformB := Platform{Name: "Godzilla", Weight: 100, HashAlgo: "SHA2", KeyAlgo: "ECDSA256", KeyStoreFile: "testdata/godzilla.pem"}
	platformC := Platform{Name: "Pineapple", Weight: 100, HashAlgo: "SHA2", KeyAlgo: "ECDSA256", KeyStoreFile: "testdata/pineapple.pem"}
	platformA.ParseAndLoad()
	platformB.ParseAndLoad()
	platformC.ParseAndLoad()
	Platforms = []Platform{platformA, platformB, platformC}
	// chain1 with root cert1 (RSA1024, SHA1), has the largest platform coverage.
	// chain2 with root cert2 (RSA2048, SHA2), has the second largest coverage.
	// chain3 with root cert3 (ECDSA256, SHA2), has the least coverage.
	chain1 := []*x509.Certificate{cert1}
	chain2 := []*x509.Certificate{cert1, cert2}
	chain3 := []*x509.Certificate{cert1, cert2, cert3}
	if CrossPlatformUbiquity(chain1) < CrossPlatformUbiquity(chain2) {
		t.Fatal("Incorrect cross platform ubiquity")
	}
	if CrossPlatformUbiquity(chain2) < CrossPlatformUbiquity(chain3) {
		t.Fatal("Incorrect cross platform ubiquity")
	}
}

func TestPlatformCryptoUbiquity(t *testing.T) {
	cert1 := rsa1024Cert
	cert2 := rsa2048Cert
	cert3 := ecdsa256Cert
	// load Platforms with test data
	// All platforms have the same trust store but are with various crypto suite.
	platformA := Platform{Name: "TinySoft", Weight: 100, HashAlgo: "SHA1", KeyAlgo: "RSA", KeyStoreFile: "testdata/macrosoft.pem"}
	platformB := Platform{Name: "SmallSoft", Weight: 100, HashAlgo: "SHA2", KeyAlgo: "RSA", KeyStoreFile: "testdata/macrosoft.pem"}
	platformC := Platform{Name: "LargeSoft", Weight: 100, HashAlgo: "SHA2", KeyAlgo: "ECDSA256", KeyStoreFile: "testdata/macrosoft.pem"}
	platformA.ParseAndLoad()
	platformB.ParseAndLoad()
	platformC.ParseAndLoad()
	Platforms = []Platform{platformA, platformB, platformC}
	// chain1 with root cert1 (RSA1024, SHA1), has the largest platform coverage.
	// chain2 with root cert2 (RSA2048, SHA2), has the second largest coverage.
	// chain3 with root cert3 (ECDSA256, SHA2), has the least coverage.
	chain1 := []*x509.Certificate{cert1}
	chain2 := []*x509.Certificate{cert1, cert2}
	chain3 := []*x509.Certificate{cert1, cert2, cert3}
	if CrossPlatformUbiquity(chain1) < CrossPlatformUbiquity(chain2) {
		t.Fatal("Incorrect cross platform ubiquity")
	}
	if CrossPlatformUbiquity(chain2) < CrossPlatformUbiquity(chain3) {
		t.Fatal("Incorrect cross platform ubiquity")
	}
}

func TestPlatformCryptoDeprecation(t *testing.T) {
	cert1 := rsa1024Cert
	cert2 := rsa2048Cert
	pweight1 := 1
	pweight2 := 10
	pweight3 := 100
	Jan1st2014 := time.Date(2014, time.January, 1, 0, 0, 0, 0, time.UTC)
	Jan1st2100 := time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC)
	DeprecationPolicy2014 := &CryptoDeprecationPolicy{Target: "SHA1", EffectiveDate: Jan1st2014, ExpiryDeadline: Jan1st2014}
	DeprecationPolicy2100 := &CryptoDeprecationPolicy{Target: "SHA2", EffectiveDate: Jan1st2100, ExpiryDeadline: Jan1st2014}
	// All platforms have the same trust store but are with various crypto suite and deprecation policy.
	// platformA supports SHA1 only and has no deprecation plan of SHA1.
	// platformB supports SHA1/SHA2 and will deprecate SHA1 at year 2100.
	// platformC supports SHA1/SHA2 and will deprecate SHA1 at year 2014.
	platformA := Platform{Name: "TinySoft", Weight: pweight1, HashAlgo: "SHA1", KeyAlgo: "RSA", KeyStoreFile: "testdata/macrosoft.pem"}
	platformB := Platform{Name: "SmallSoft", Weight: pweight2, HashAlgo: "SHA2", KeyAlgo: "RSA", KeyStoreFile: "testdata/macrosoft.pem", HashDeprecation: DeprecationPolicy2100}
	platformC := Platform{Name: "LargeSoft", Weight: pweight3, HashAlgo: "SHA2", KeyAlgo: "RSA", KeyStoreFile: "testdata/macrosoft.pem", HashDeprecation: DeprecationPolicy2014}
	platformA.ParseAndLoad()
	platformB.ParseAndLoad()
	platformC.ParseAndLoad()
	Platforms = []Platform{platformA, platformB, platformC}
	// chain1 is accepted by platform A, B and C. It's not rejected by platFormC because root cert is not subject to SHA1 deprecation.
	chain1 := []*x509.Certificate{cert1}
	// chain2 is accepted by platform A, B. It's rejected by platFormC because leaf cert is subject to SHA1 deprecation.
	chain2 := []*x509.Certificate{cert1, cert1}
	// chain3 is accepted by platformB and platFormC. It's rejected by platformA due to A's inablity to support SHA2.
	chain3 := []*x509.Certificate{cert2, cert1}

	if CrossPlatformUbiquity(chain1) != pweight1+pweight2+pweight3 {
		t.Fatal("Incorrect cross platform ubiquity: ", CrossPlatformUbiquity(chain1))
	}
	if CrossPlatformUbiquity(chain2) != pweight1+pweight2 {
		t.Fatal("Incorrect cross platform ubiquity: ", CrossPlatformUbiquity(chain2))
	}
	if CrossPlatformUbiquity(chain3) != pweight2+pweight3 {
		t.Fatal("Incorrect cross platform ubiquity: ", CrossPlatformUbiquity(chain3))
	}

	dplatforms := DeprecatedSHA1Platforms(chain2)
	if len(dplatforms) != 1 || dplatforms[0] != "LargeSoft" {
		t.Fatal("Incorrect deprecation checking: ", dplatforms)
	}
}

func TestSHA2Homogeneity(t *testing.T) {
	// root-only chain is always SHA2-Homogeneous.
	chain0 := []*x509.Certificate{rsa1024Cert}
	if SHA2Homogeneity(chain0) != 1 {
		t.Fatal("SHA2Homogeneity(chain0) != 1")
	}

	chain1 := []*x509.Certificate{rsa1024Cert, rsa2048Cert, rsa1024Cert}
	if SHA2Homogeneity(chain1) != 0 {
		t.Fatal("SHA2Homogeneity(chain1) != 0")
	}

	chain2 := []*x509.Certificate{rsa2048Cert, rsa2048Cert, rsa1024Cert}
	if SHA2Homogeneity(chain2) != 1 {
		t.Fatal("SHA2Homogeneity(chain2) != 1")
	}

	chain3 := []*x509.Certificate{ecdsa256Cert, rsa2048Cert, rsa1024Cert}
	if SHA2Homogeneity(chain3) != 1 {
		t.Fatal("SHA2Homogeneity(chain3) != 1")
	}

	chain4 := []*x509.Certificate{ecdsa256Cert, ecdsa384Cert, rsa1024Cert}
	if SHA2Homogeneity(chain4) != 1 {
		t.Fatal("SHA2Homogeneity(chain4) != 1")
	}
}

func TestCompareSHA2Homogeneity(t *testing.T) {
	chain1 := []*x509.Certificate{rsa1024Cert, rsa2048Cert, rsa1024Cert}
	chain2 := []*x509.Certificate{rsa2048Cert, rsa2048Cert, rsa1024Cert}
	chain3 := []*x509.Certificate{ecdsa256Cert, rsa2048Cert, rsa1024Cert}
	chain4 := []*x509.Certificate{ecdsa256Cert, ecdsa384Cert, rsa1024Cert}
	if CompareSHA2Homogeneity(chain1, chain2) >= 0 {
		t.Fatal("CompareSHA2Homogeneity(chain1, chain2) >= 0")
	}

	if CompareSHA2Homogeneity(chain1, chain3) >= 0 {
		t.Fatal("CompareSHA2Homogeneity(chain1, chain3) >= 0")
	}

	if CompareSHA2Homogeneity(chain1, chain4) >= 0 {
		t.Fatal("CompareSHA2Homogeneity(chain1, chain4) >= 0")
	}

	if CompareSHA2Homogeneity(chain2, chain3) != 0 || CompareSHA2Homogeneity(chain3, chain4) != 0 {
		t.Fatal("CompareSHA2Homogeneity failed.")
	}
}
