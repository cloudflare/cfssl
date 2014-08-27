package signer

import (
	"crypto/x509"
	"io/ioutil"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/helpers"
)

const (
	testCaFile            = "testdata/ca.pem"
	testCaKeyFile         = "testdata/ca_key.pem"
	testECDSACaFile       = "testdata/ecdsa256_ca.pem"
	testECDSACaKeyFile    = "testdata/ecdsa256_ca_key.pem"
	testClientCertFile    = "testdata/cert.pem"
	testBrokenCertFile    = "testdata/broken.pem"
	testNotSelfSignedFile = "testdata/notselfsigned.pem"
)

var expiry = 1 * time.Minute

// Start a signer with the testing RSA CA cert and key.
func newTestSigner(t *testing.T) (s Signer) {
	s, err := NewSigner(testCaFile, testCaKeyFile, nil)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestNewSignerPolicy(t *testing.T) {
	var CAConfig = &config.Config{
		Signing: &config.Signing{
			Profiles: map[string]*config.SigningProfile{
				"signature": &config.SigningProfile{
					Usage:  []string{"digital signature"},
					Expiry: expiry,
				},
			},
			Default: &config.SigningProfile{
				Usage:        []string{"cert sign", "crl sign"},
				ExpiryString: "43800h",
				Expiry:       expiry,
				CA:           true,
			},
		},
	}
	_, err := NewSigner(testCaFile, testCaKeyFile, CAConfig.Signing)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewSignerInvalidPolicy(t *testing.T) {
	var invalidConfig = &config.Config{
		Signing: &config.Signing{
			Profiles: map[string]*config.SigningProfile{
				"invalid": &config.SigningProfile{
					Usage:  []string{"wiretapping"},
					Expiry: expiry,
				},
				"empty": &config.SigningProfile{},
			},
			Default: &config.SigningProfile{
				Usage:  []string{"digital signature"},
				Expiry: expiry,
			},
		},
	}
	_, err := NewSigner(testCaFile, testCaKeyFile, invalidConfig.Signing)
	if err == nil {
		t.Fatal(err)
	}

}

func newCustomSigner(t *testing.T, testCaFile, testCaKeyFile string) (s Signer) {
	s, err := NewSigner(testCaFile, testCaKeyFile, nil)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestNewSigner(t *testing.T) {
	newTestSigner(t)
}

const (
	testHostName = "localhost"
)

func TestSign(t *testing.T) {
	signer := newTestSigner(t)

	clientCertPEM, err := ioutil.ReadFile(testClientCertFile)
	if err != nil {
		t.Fatal(err)
	}
	clientCert, err := helpers.ParseCertificatePEM(clientCertPEM)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := signer.Sign(testHostName, clientCertPEM, "")
	if err != nil {
		t.Fatal(err)
	}

	cert, err := helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.CheckSignatureFrom(signer.(*StandardSigner).ca); err != nil {
		t.Fatal(err)
	}
	if err := cert.VerifyHostname(testHostName); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cert.PublicKey, clientCert.PublicKey) {
		t.Fatal("Cert public key does not match clientCert", cert.PublicKey, clientCert.PublicKey)
	}
}

func testSignFile(t *testing.T, certFile string) ([]byte, error) {
	signer := newTestSigner(t)

	pem, err := ioutil.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}

	return signer.Sign(testHostName, pem, "")
}

func TestBrokenCert(t *testing.T) {
	if _, err := testSignFile(t, testBrokenCertFile); err == nil {
		t.Fatal("Broken Certificate did not fail")
	}
}

func TestNotSelfSignedCert(t *testing.T) {
	if _, err := testSignFile(t, testNotSelfSignedFile); !strings.Contains(err.Error(), "\"code\":1200") {
		t.Fatal(err)
	}
}

type csrTest struct {
	file    string
	keyAlgo string
	keyLen  int
	// Error checking function
	errorCallback func(*testing.T, error)
}

// A helper function that returns a errorCallback function which expects an error.
func ExpectError() func(*testing.T, error) {
	return func(t *testing.T, err error) {
		if err == nil {
			t.Fatal("Expected error. Got nothing.")
		}
	}
}

var csrTests = []csrTest{
	{
		file:          "testdata/rsa2048.csr",
		keyAlgo:       "rsa",
		keyLen:        2048,
		errorCallback: nil,
	},
	{
		file:          "testdata/rsa3072.csr",
		keyAlgo:       "rsa",
		keyLen:        3072,
		errorCallback: nil,
	},
	{
		file:          "testdata/rsa4096.csr",
		keyAlgo:       "rsa",
		keyLen:        4096,
		errorCallback: nil,
	},
	{
		file:          "testdata/ecdsa256.csr",
		keyAlgo:       "ecdsa",
		keyLen:        256,
		errorCallback: nil,
	},
	{
		file:          "testdata/ecdsa384.csr",
		keyAlgo:       "ecdsa",
		keyLen:        384,
		errorCallback: nil,
	},
	{
		file:          "testdata/ecdsa521.csr",
		keyAlgo:       "ecdsa",
		keyLen:        521,
		errorCallback: nil,
	},
}

func TestSignCSRs(t *testing.T) {
	signer := newTestSigner(t)
	hostname := "cloudflare.com"
	for _, test := range csrTests {
		csr, err := ioutil.ReadFile(test.file)
		if err != nil {
			t.Fatal("CSR loading error:", err)
		}
		// It is possible to use different SHA2 algorithm with RSA CA key.
		rsaSigAlgos := []x509.SignatureAlgorithm{x509.SHA1WithRSA, x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA}
		for _, sigAlgo := range rsaSigAlgos {
			signer.(*StandardSigner).sigAlgo = sigAlgo
			certBytes, err := signer.Sign(hostname, csr, "")
			if test.errorCallback != nil {
				test.errorCallback(t, err)
			} else {
				if err != nil {
					t.Fatalf("Expected no error. Got %s. Param %s %d", err.Error(), test.keyAlgo, test.keyLen)
				}
				cert, _ := helpers.ParseCertificatePEM(certBytes)
				if cert.SignatureAlgorithm != signer.SigAlgo() {
					t.Fatal("Cert Signature Algorithm does not match the issuer.")
				}
			}
		}
	}
}

func TestECDSASigner(t *testing.T) {
	signer := newCustomSigner(t, testECDSACaFile, testECDSACaKeyFile)
	hostname := "cloudflare.com"
	for _, test := range csrTests {
		csr, err := ioutil.ReadFile(test.file)
		if err != nil {
			t.Fatal("CSR loading error:", err)
		}
		// Try all ECDSA SignatureAlgorithm
		SigAlgos := []x509.SignatureAlgorithm{x509.ECDSAWithSHA1, x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512}
		for _, sigAlgo := range SigAlgos {
			signer.(*StandardSigner).sigAlgo = sigAlgo
			certBytes, err := signer.Sign(hostname, csr, "")
			if test.errorCallback != nil {
				test.errorCallback(t, err)
			} else {
				if err != nil {
					t.Fatalf("Expected no error. Got %s. Param %s %d", err.Error(), test.keyAlgo, test.keyLen)
				}
				cert, _ := helpers.ParseCertificatePEM(certBytes)
				if cert.SignatureAlgorithm != signer.SigAlgo() {
					t.Fatal("Cert Signature Algorithm does not match the issuer.")
				}
			}
		}
	}
}

const (
	ecdsaInterCSR = "testdata/ecdsa256-inter.csr"
	ecdsaInterKey = "testdata/ecdsa256-inter.key"
	rsaInterCSR   = "testdata/rsa2048-inter.csr"
	rsaInterKey   = "testdata/rsa2048-inter.key"
)

func TestCAIssuing(t *testing.T) {
	var caCerts = []string{testCaFile, testECDSACaFile}
	var caKeys = []string{testCaKeyFile, testECDSACaKeyFile}
	var interCSRs = []string{ecdsaInterCSR, rsaInterCSR}
	var interKeys = []string{ecdsaInterKey, rsaInterKey}
	var CAPolicy = &config.Signing{
		Default: &config.SigningProfile{
			Usage:        []string{"cert sign", "crl sign"},
			ExpiryString: "1h",
			Expiry:       1 * time.Hour,
			CA:           true,
		},
	}
	var hostname = "cloudflare-inter.com"
	// Each RSA or ECDSA root CA issues two intermediate CAs (one ECDSA and one RSA).
	// For each intermediate CA, use it to issue additional RSA and ECDSA intermediate CSRs.
	for i, caFile := range caCerts {
		caKeyFile := caKeys[i]
		signer := newCustomSigner(t, caFile, caKeyFile)
		signer.(*StandardSigner).policy = CAPolicy
		for j, csr := range interCSRs {
			csrBytes, _ := ioutil.ReadFile(csr)
			certBytes, err := signer.Sign(hostname, csrBytes, "")
			if err != nil {
				t.Fatal(err)
			}
			interCert, err := helpers.ParseCertificatePEM(certBytes)
			if err != nil {
				t.Fatal(err)
			}
			keyBytes, _ := ioutil.ReadFile(interKeys[j])
			interKey, _ := helpers.ParsePrivateKeyPEM(keyBytes)
			interSigner := &StandardSigner{interCert, interKey, CAPolicy, DefaultSigAlgo(interKey)}
			for _, anotherCSR := range interCSRs {
				anotherCSRBytes, _ := ioutil.ReadFile(anotherCSR)
				bytes, err := interSigner.Sign(hostname, anotherCSRBytes, "")
				if err != nil {
					t.Fatal(err)
				}
				cert, err := helpers.ParseCertificatePEM(bytes)
				if err != nil {
					t.Fatal(err)
				}
				if cert.SignatureAlgorithm != interSigner.SigAlgo() {
					t.Fatal("Cert Signature Algorithm does not match the issuer.")
				}
			}
		}
	}

}
