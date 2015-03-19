package local

import (
	"crypto/x509"
	"io/ioutil"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
)

const (
	testCaFile         = "testdata/ca.pem"
	testCaKeyFile      = "testdata/ca_key.pem"
	testECDSACaFile    = "testdata/ecdsa256_ca.pem"
	testECDSACaKeyFile = "testdata/ecdsa256_ca_key.pem"
)

var expiry = 1 * time.Minute

// Start a signer with the testing RSA CA cert and key.
func newTestSigner(t *testing.T) (s *Signer) {
	s, err := NewSignerFromFile(testCaFile, testCaKeyFile, nil)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestNewSignerFromFilePolicy(t *testing.T) {
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
	_, err := NewSignerFromFile(testCaFile, testCaKeyFile, CAConfig.Signing)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewSignerFromFileInvalidPolicy(t *testing.T) {
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
	_, err := NewSignerFromFile(testCaFile, testCaKeyFile, invalidConfig.Signing)
	if err == nil {
		t.Fatal(err)
	}

	if !strings.Contains(err.Error(), `"code":5200`) {
		t.Fatal(err)
	}
}

func TestNewSignerFromFileNoUsageInPolicy(t *testing.T) {
	var invalidConfig = &config.Config{
		Signing: &config.Signing{
			Profiles: map[string]*config.SigningProfile{
				"invalid": &config.SigningProfile{
					Usage:  []string{},
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
	_, err := NewSignerFromFile(testCaFile, testCaKeyFile, invalidConfig.Signing)
	if err == nil {
		t.Fatal("expect InvalidPolicy error")
	}

	if !strings.Contains(err.Error(), `"code":5200`) {
		t.Fatal(err)
	}
}

func TestNewSignerFromFileEdgeCases(t *testing.T) {

	res, err := NewSignerFromFile("nil", "nil", nil)
	if res != nil && err == nil {
		t.Fatal("Incorrect inputs failed to produce correct results")
	}

	res, err = NewSignerFromFile(testCaFile, "nil", nil)
	if res != nil && err == nil {
		t.Fatal("Incorrect inputs failed to produce correct results")
	}

	res, err = NewSignerFromFile("../../helpers/testdata/messedupcert.pem", "local.go", nil)
	if res != nil && err == nil {
		t.Fatal("Incorrect inputs failed to produce correct results")
	}

	res, err = NewSignerFromFile("../../helpers/testdata/cert.pem", "../../helpers/testdata/messed_up_priv_key.pem", nil)
	if res != nil && err == nil {
		t.Fatal("Incorrect inputs failed to produce correct results")
	}
}

// test the private method
func testSign(t *testing.T) {
	signer, err := NewSignerFromFile("testdata/ca.pem", "testdata/ca_key.pem", nil)
	if signer == nil || err != nil {
		t.Fatal("Failed to produce signer")
	}

	pem, _ := ioutil.ReadFile("../../helpers/testdata/cert.pem")
	cert, _ := helpers.ParseCertificatePEM(pem)

	badcert := *cert
	badcert.PublicKey = nil
	profl := config.SigningProfile{Usage: []string{"Certificates", "Rule"}}
	_, err = signer.sign(&badcert, &profl)

	if err == nil {
		t.Fatal("Improper input failed to raise an error")
	}

	// nil profile
	_, err = signer.sign(cert, &profl)
	if err == nil {
		t.Fatal("Nil profile failed to raise an error")
	}

	// empty profile
	_, err = signer.sign(cert, &config.SigningProfile{})
	if err == nil {
		t.Fatal("Empty profile failed to raise an error")
	}

	// empty expiry
	prof := signer.policy.Default
	prof.Expiry = 0
	_, err = signer.sign(cert, prof)
	if err != nil {
		t.Fatal("nil expiry raised an error")
	}

	// non empty urls
	prof = signer.policy.Default
	prof.CRL = "stuff"
	prof.OCSP = "stuff"
	prof.IssuerURL = []string{"stuff"}
	_, err = signer.sign(cert, prof)
	if err != nil {
		t.Fatal("non nil urls raised an error")
	}

	// nil ca
	nilca := *signer
	prof = signer.policy.Default
	prof.CA = false
	nilca.ca = nil
	_, err = nilca.sign(cert, prof)
	if err == nil {
		t.Fatal("nil ca with isca false raised an error")
	}
	prof.CA = true
	_, err = nilca.sign(cert, prof)
	if err != nil {
		t.Fatal("nil ca with CA true raised an error")
	}
}

func TestSign(t *testing.T) {
	testSign(t)
	s, err := NewSignerFromFile("testdata/ca.pem", "testdata/ca_key.pem", nil)
	if err != nil {
		t.Fatal("Failed to produce signer")
	}

	// test the empty request
	_, err = s.Sign(signer.SignRequest{})
	if err == nil {
		t.Fatalf("Empty request failed to produce an error")
	}

	// not a csr
	certPem, err := ioutil.ReadFile("../../helpers/testdata/cert.pem")
	if err != nil {
		t.Fatal(err)
	}

	// csr with ip as hostname
	pem, err := ioutil.ReadFile("testdata/ip.csr")
	if err != nil {
		t.Fatal(err)
	}

	// improper request
	validReq := signer.SignRequest{Hosts: signer.SplitHosts(testHostName), Request: string(certPem)}
	_, err = s.Sign(validReq)
	if err == nil {
		t.Fatal("A bad case failed to raise an error")
	}

	validReq = signer.SignRequest{Hosts: signer.SplitHosts("128.84.126.213"), Request: string(pem)}
	_, err = s.Sign(validReq)
	if err != nil {
		t.Fatal("A bad case failed to raise an error")
	}

	pem, err = ioutil.ReadFile("testdata/ex.csr")
	validReq = signer.SignRequest{
		Request: string(pem),
		Hosts:   []string{"example.com"},
	}
	s.Sign(validReq)
	if err != nil {
		t.Fatal("Failed to sign")
	}
}

func TestCertificate(t *testing.T) {
	s, err := NewSignerFromFile("testdata/ca.pem", "testdata/ca_key.pem", nil)
	if err != nil {
		t.Fatal(err)
	}

	c, err := s.Certificate("", "")
	if !reflect.DeepEqual(*c, *s.ca) || err != nil {
		t.Fatal("Certificate() producing incorrect results")
	}
}

func TestPolicy(t *testing.T) {
	s, err := NewSignerFromFile("testdata/ca.pem", "testdata/ca_key.pem", nil)
	if err != nil {
		t.Fatal(err)
	}

	sgn := config.Signing{}

	s.SetPolicy(&sgn)
	if s.Policy() != &sgn {
		t.Fatal("Policy is malfunctioning")
	}
}

func newCustomSigner(t *testing.T, testCaFile, testCaKeyFile string) (s *Signer) {
	s, err := NewSignerFromFile(testCaFile, testCaKeyFile, nil)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestNewSignerFromFile(t *testing.T) {
	newTestSigner(t)
}

const (
	testHostName = "localhost"
)

func testSignFile(t *testing.T, certFile string) ([]byte, error) {
	s := newTestSigner(t)

	pem, err := ioutil.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}

	return s.Sign(signer.SignRequest{Hosts: signer.SplitHosts(testHostName), Request: string(pem)})
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
	s := newTestSigner(t)
	hostname := "cloudflare.com"
	for _, test := range csrTests {
		csr, err := ioutil.ReadFile(test.file)
		if err != nil {
			t.Fatal("CSR loading error:", err)
		}
		// It is possible to use different SHA2 algorithm with RSA CA key.
		rsaSigAlgos := []x509.SignatureAlgorithm{x509.SHA1WithRSA, x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA}
		for _, sigAlgo := range rsaSigAlgos {
			s.sigAlgo = sigAlgo
			certBytes, err := s.Sign(signer.SignRequest{Hosts: signer.SplitHosts(hostname), Request: string(csr)})
			if test.errorCallback != nil {
				test.errorCallback(t, err)
			} else {
				if err != nil {
					t.Fatalf("Expected no error. Got %s. Param %s %d", err.Error(), test.keyAlgo, test.keyLen)
				}
				cert, _ := helpers.ParseCertificatePEM(certBytes)
				if cert.SignatureAlgorithm != s.SigAlgo() {
					t.Fatal("Cert Signature Algorithm does not match the issuer.")
				}
			}
		}
	}
}

func TestECDSASigner(t *testing.T) {
	s := newCustomSigner(t, testECDSACaFile, testECDSACaKeyFile)
	hostname := "cloudflare.com"
	for _, test := range csrTests {
		csr, err := ioutil.ReadFile(test.file)
		if err != nil {
			t.Fatal("CSR loading error:", err)
		}
		// Try all ECDSA SignatureAlgorithm
		SigAlgos := []x509.SignatureAlgorithm{x509.ECDSAWithSHA1, x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512}
		for _, sigAlgo := range SigAlgos {
			s.sigAlgo = sigAlgo
			certBytes, err := s.Sign(signer.SignRequest{Hosts: signer.SplitHosts(hostname), Request: string(csr)})
			if test.errorCallback != nil {
				test.errorCallback(t, err)
			} else {
				if err != nil {
					t.Fatalf("Expected no error. Got %s. Param %s %d", err.Error(), test.keyAlgo, test.keyLen)
				}
				cert, _ := helpers.ParseCertificatePEM(certBytes)
				if cert.SignatureAlgorithm != s.SigAlgo() {
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
		s := newCustomSigner(t, caFile, caKeyFile)
		s.policy = CAPolicy
		for j, csr := range interCSRs {
			csrBytes, _ := ioutil.ReadFile(csr)
			certBytes, err := s.Sign(signer.SignRequest{Hosts: signer.SplitHosts(hostname), Request: string(csrBytes)})
			if err != nil {
				t.Fatal(err)
			}
			interCert, err := helpers.ParseCertificatePEM(certBytes)
			if err != nil {
				t.Fatal(err)
			}
			keyBytes, _ := ioutil.ReadFile(interKeys[j])
			interKey, _ := helpers.ParsePrivateKeyPEM(keyBytes)
			interSigner := &Signer{interCert, interKey, CAPolicy, signer.DefaultSigAlgo(interKey)}
			for _, anotherCSR := range interCSRs {
				anotherCSRBytes, _ := ioutil.ReadFile(anotherCSR)
				bytes, err := interSigner.Sign(
					signer.SignRequest{
						Hosts:   signer.SplitHosts(hostname),
						Request: string(anotherCSRBytes),
					})
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

const testCSR = "testdata/ecdsa256.csr"

func TestOverrideSubject(t *testing.T) {
	csrPEM, err := ioutil.ReadFile(testCSR)
	if err != nil {
		t.Fatalf("%v", err)
	}

	req := &signer.Subject{
		Names: []csr.Name{
			{O: "example.net"},
		},
	}

	s := newCustomSigner(t, testECDSACaFile, testECDSACaKeyFile)

	request := signer.SignRequest{
		Hosts:   []string{"127.0.0.1", "localhost"},
		Request: string(csrPEM),
		Subject: req,
	}
	certPEM, err := s.Sign(request)

	if err != nil {
		t.Fatalf("%v", err)
	}

	cert, err := helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if cert.Subject.Organization[0] != "example.net" {
		t.Fatalf("Failed to override subject: want example.net but have %s", cert.Subject.Organization[0])
	}

	log.Info("Overrode subject info")
}

func TestOverwriteHosts(t *testing.T) {
	csrPEM, err := ioutil.ReadFile(testCSR)
	if err != nil {
		t.Fatalf("%v", err)
	}

	s := newCustomSigner(t, testECDSACaFile, testECDSACaKeyFile)

	request := signer.SignRequest{
		Hosts:   []string{"127.0.0.1", "localhost"},
		Request: string(csrPEM),
		Subject: nil,
	}
	certPEM, err := s.Sign(request)

	if err != nil {
		t.Fatalf("%v", err)
	}

	cert, err := helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// get the hosts, and add the ips
	hosts, ips := cert.DNSNames, cert.IPAddresses
	for _, ip := range ips {
		hosts = append(hosts, ip.String())
	}

	// compare the sorted host lists
	sort.Strings(hosts)
	sort.Strings(request.Hosts)
	if !reflect.DeepEqual(hosts, request.Hosts) {
		t.Fatalf("Hosts not the same. cert hosts: %v, expected: %v", hosts, request.Hosts)
	}

	log.Info("Overwrote hosts")

}
