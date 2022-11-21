package local

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"

	"github.com/google/certificate-transparency-go"
	"github.com/zmap/zlint/v3/lint"
)

const (
	fullSubjectCSR     = "testdata/test.csr"
	testCSR            = "testdata/ecdsa256.csr"
	testSANCSR         = "testdata/san_domain.csr"
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
				"signature": {
					Usage:  []string{"digital signature"},
					Expiry: expiry,
				},
			},
			Default: &config.SigningProfile{
				Usage:        []string{"cert sign", "crl sign"},
				ExpiryString: "43800h",
				Expiry:       expiry,
				CAConstraint: config.CAConstraint{IsCA: true},
			},
		},
	}
	signer, err := NewSignerFromFile(testCaFile, testCaKeyFile, CAConfig.Signing)
	if err != nil {
		t.Fatal(err)
	}
	if signer.lintPriv != nil {
		t.Error("expected signer with LintErrLevel == 0 to have lintPriv == nil")
	}
}

func TestNewSignerFromFileInvalidPolicy(t *testing.T) {
	var invalidConfig = &config.Config{
		Signing: &config.Signing{
			Profiles: map[string]*config.SigningProfile{
				"invalid": {
					Usage:  []string{"wiretapping"},
					Expiry: expiry,
				},
				"empty": {},
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
				"invalid": {
					Usage:  []string{},
					Expiry: expiry,
				},
				"empty": {},
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

func TestNewSignerFromFilePolicyLinting(t *testing.T) {
	// CAConfig is a config that has an explicit "signature" profile that enables
	// pre-issuance linting.
	var CAConfig = &config.Config{
		Signing: &config.Signing{
			Profiles: map[string]*config.SigningProfile{
				"signature": {
					Usage:        []string{"digital signature"},
					Expiry:       expiry,
					LintErrLevel: 3,
				},
			},
			Default: &config.SigningProfile{
				Usage:        []string{"cert sign", "crl sign"},
				ExpiryString: "43800h",
				Expiry:       expiry,
				CAConstraint: config.CAConstraint{IsCA: true},
			},
		},
	}
	signer, err := NewSignerFromFile(testCaFile, testCaKeyFile, CAConfig.Signing)
	if err != nil {
		t.Fatal(err)
	}
	// A CAConfig with a signing profile that sets LintErrLevel > 0 should have
	// a lintPriv key generated.
	if signer.lintPriv == nil {
		t.Error("expected signer with profile LintErrLevel > 0 to have lintPriv != nil")
	}

	// Reconfigure caConfig so that the explicit "signature" profile doesn't
	// enable pre-issuance linting but the default profile does.
	CAConfig.Signing.Profiles["signature"].LintErrLevel = 0
	CAConfig.Signing.Default.LintErrLevel = 3
	signer, err = NewSignerFromFile(testCaFile, testCaKeyFile, CAConfig.Signing)
	if err != nil {
		t.Fatal(err)
	}
	// A CAConfig with a default profile that sets LintErrLevel > 0 should have
	// a lintPriv key generated.
	if signer.lintPriv == nil {
		t.Error("expected signer with default profile LintErrLevel > 0 to have lintPriv != nil")
	}
}

func TestSign(t *testing.T) {
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
	certPem, err := os.ReadFile("../../helpers/testdata/cert.pem")
	if err != nil {
		t.Fatal(err)
	}

	// csr with ip as hostname
	pem, err := os.ReadFile("testdata/ip.csr")
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

	pem, err = os.ReadFile("testdata/ex.csr")
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

	pem, err := os.ReadFile(certFile)
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
	{
		file:          "testdata/rsa-old.csr",
		keyAlgo:       "rsa",
		keyLen:        2048,
		errorCallback: nil,
	},
}

func TestSignCSRs(t *testing.T) {
	s := newTestSigner(t)
	hostname := "cloudflare.com"
	for _, test := range csrTests {
		csr, err := os.ReadFile(test.file)
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
		csr, err := os.ReadFile(test.file)
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
			CAConstraint: config.CAConstraint{IsCA: true, MaxPathLenZero: true},
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
			csrBytes, _ := os.ReadFile(csr)
			certBytes, err := s.Sign(signer.SignRequest{Hosts: signer.SplitHosts(hostname), Request: string(csrBytes)})
			if err != nil {
				t.Fatal(err)
			}
			interCert, err := helpers.ParseCertificatePEM(certBytes)
			if err != nil {
				t.Fatal(err)
			}
			keyBytes, _ := os.ReadFile(interKeys[j])
			interKey, _ := helpers.ParsePrivateKeyPEM(keyBytes)
			interSigner := &Signer{
				ca:      interCert,
				priv:    interKey,
				policy:  CAPolicy,
				sigAlgo: signer.DefaultSigAlgo(interKey),
			}
			for _, anotherCSR := range interCSRs {
				anotherCSRBytes, _ := os.ReadFile(anotherCSR)
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
				if cert.MaxPathLen != 0 {
					t.Fatal("CA Cert Max Path is not zero.")
				}
				if cert.MaxPathLenZero != true {
					t.Fatal("CA Cert Max Path is not zero.")
				}
			}
		}
	}

}

func TestPopulateSubjectFromCSR(t *testing.T) {
	// a subject with all its fields full.
	fullSubject := &signer.Subject{
		CN: "CN",
		Names: []csr.Name{
			{
				C:  "C",
				ST: "ST",
				L:  "L",
				O:  "O",
				OU: "OU",
			},
		},
		SerialNumber: "deadbeef",
	}

	fullName := pkix.Name{
		CommonName:         "CommonName",
		Country:            []string{"Country"},
		Province:           []string{"Province"},
		Organization:       []string{"Organization"},
		OrganizationalUnit: []string{"OrganizationalUnit"},
		SerialNumber:       "SerialNumber",
	}

	noCN := *fullSubject
	noCN.CN = ""
	name := PopulateSubjectFromCSR(&noCN, fullName)
	if name.CommonName != "CommonName" {
		t.Fatal("Failed to replace empty common name")
	}

	noC := *fullSubject
	noC.Names[0].C = ""
	name = PopulateSubjectFromCSR(&noC, fullName)
	if !reflect.DeepEqual(name.Country, fullName.Country) {
		t.Fatal("Failed to replace empty country")
	}

	noL := *fullSubject
	noL.Names[0].L = ""
	name = PopulateSubjectFromCSR(&noL, fullName)
	if !reflect.DeepEqual(name.Locality, fullName.Locality) {
		t.Fatal("Failed to replace empty locality")
	}

	noO := *fullSubject
	noO.Names[0].O = ""
	name = PopulateSubjectFromCSR(&noO, fullName)
	if !reflect.DeepEqual(name.Organization, fullName.Organization) {
		t.Fatal("Failed to replace empty organization")
	}

	noOU := *fullSubject
	noOU.Names[0].OU = ""
	name = PopulateSubjectFromCSR(&noOU, fullName)
	if !reflect.DeepEqual(name.OrganizationalUnit, fullName.OrganizationalUnit) {
		t.Fatal("Failed to replace empty organizational unit")
	}

	noSerial := *fullSubject
	noSerial.SerialNumber = ""
	name = PopulateSubjectFromCSR(&noSerial, fullName)
	if name.SerialNumber != fullName.SerialNumber {
		t.Fatalf("Failed to replace empty serial number: want %#v, got %#v", fullName.SerialNumber, name.SerialNumber)
	}

}
func TestOverrideSubject(t *testing.T) {
	csrPEM, err := os.ReadFile(fullSubjectCSR)
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
		Hosts:   []string{"127.0.0.1", "localhost", "xyz@example.com", "https://www.cloudflare.com"},
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

	block, _ := pem.Decode(csrPEM)
	template, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err.Error())
	}
	if cert.Subject.Organization[0] != "example.net" {
		t.Fatalf("Failed to override subject: want example.net but have %s", cert.Subject.Organization[0])
	}

	if cert.Subject.Country[0] != template.Subject.Country[0] {
		t.Fatal("Failed to override Country")
	}

	if cert.Subject.Locality[0] != template.Subject.Locality[0] {
		t.Fatal("Failed to override Locality")
	}

	if cert.Subject.Organization[0] == template.Subject.Organization[0] {
		t.Fatal("Shouldn't have overrode Organization")
	}

	if cert.Subject.OrganizationalUnit[0] != template.Subject.OrganizationalUnit[0] {
		t.Fatal("Failed to override OrganizationalUnit")
	}

	log.Info("Overrode subject info")
}

func TestOverwriteHosts(t *testing.T) {
	for _, csrFile := range []string{testCSR, testSANCSR} {
		csrPEM, err := os.ReadFile(csrFile)
		if err != nil {
			t.Fatal(err)
		}

		csrDER, _ := pem.Decode([]byte(csrPEM))
		if err != nil {
			t.Fatal(err)
		}

		csr, err := x509.ParseCertificateRequest(csrDER.Bytes)
		if err != nil {
			t.Fatal(err)
		}

		csrHosts := csr.DNSNames
		for _, ip := range csr.IPAddresses {
			csrHosts = append(csrHosts, ip.String())
		}
		sort.Strings(csrHosts)

		s := newCustomSigner(t, testECDSACaFile, testECDSACaKeyFile)

		for _, hosts := range [][]string{
			nil,
			{},
			{"127.0.0.1", "localhost", "xyz@example.com", "https://www.cloudflare.com"},
		} {
			request := signer.SignRequest{
				Hosts:   hosts,
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

			// get the hosts, and add the ips and email addresses
			certHosts := cert.DNSNames
			for _, ip := range cert.IPAddresses {
				certHosts = append(certHosts, ip.String())
			}

			for _, email := range cert.EmailAddresses {
				certHosts = append(certHosts, email)
			}

			for _, uri := range cert.URIs {
				certHosts = append(certHosts, uri.String())
			}

			// compare the sorted host lists
			sort.Strings(certHosts)
			sort.Strings(request.Hosts)
			if len(request.Hosts) > 0 && !reflect.DeepEqual(certHosts, request.Hosts) {
				t.Fatalf("Hosts not the same. cert hosts: %v, expected: %v", certHosts, request.Hosts)
			}

			if request.Hosts == nil && !reflect.DeepEqual(certHosts, csrHosts) {
				t.Fatalf("Hosts not the same. cert hosts: %v, expected csr hosts: %v", certHosts, csrHosts)
			}

			if request.Hosts != nil && len(request.Hosts) == 0 && len(certHosts) != 0 {
				t.Fatalf("Hosts not the same. cert hosts: %v, expected: %v", certHosts, request.Hosts)
			}
		}
	}

}

func TestOverrideValidity(t *testing.T) {
	csrPEM, err := os.ReadFile(fullSubjectCSR)
	if err != nil {
		t.Fatalf("%v", err)
	}

	s := newCustomSigner(t, testECDSACaFile, testECDSACaKeyFile)

	req := signer.SignRequest{
		Request: string(csrPEM),
	}

	// The default expiry value.
	expiry := 8760 * time.Hour

	// default case
	now := time.Now().UTC()
	certPEM, err := s.Sign(req)
	if err != nil {
		t.Fatalf("Error signing default request: %s", err)
	}
	cert, err := helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if !cert.NotBefore.After(now.Add(-10*time.Minute)) || !cert.NotBefore.Before(now.Add(10*time.Minute)) {
		t.Fatalf("Unexpected NotBefore: wanted %s +/-10 minutes, got %s", now, cert.NotBefore)
	}
	expectedNotAfter := now.Round(time.Minute).Add(expiry)
	if !cert.NotAfter.After(expectedNotAfter.Add(-10*time.Minute)) || !cert.NotAfter.Before(expectedNotAfter.Add(10*time.Minute)) {
		t.Fatalf("Unexpected NotAfter: wanted %s +/-10 minutes, got %s", now, cert.NotAfter)
	}

	// custom case, NotBefore only
	now = time.Now().UTC()
	req.NotBefore = now.Add(-time.Hour * 5).Truncate(time.Hour)
	req.NotAfter = time.Time{}
	certPEM, err = s.Sign(req)
	if err != nil {
		t.Fatalf("Error signing default request: %s", err)
	}
	cert, err = helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if !cert.NotBefore.Equal(req.NotBefore) {
		t.Fatalf("Unexpected NotBefore: wanted %s, got %s", req.NotBefore, cert.NotBefore)
	}
	expectedNotAfter = req.NotBefore.Add(expiry)
	if !cert.NotAfter.After(expectedNotAfter.Add(-10*time.Minute)) || !cert.NotAfter.Before(expectedNotAfter.Add(10*time.Minute)) {
		t.Fatalf("Unexpected NotAfter: wanted %s +/-10 minutes, got %s", expectedNotAfter, cert.NotAfter)
	}

	// custom case, NotAfter only
	now = time.Now().UTC()
	req.NotBefore = time.Time{}
	req.NotAfter = now.Add(-time.Hour * 5).Truncate(time.Hour)
	certPEM, err = s.Sign(req)
	if err != nil {
		t.Fatalf("Error signing default request: %s", err)
	}
	cert, err = helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if !cert.NotBefore.After(now.Add(-10*time.Minute)) || !cert.NotBefore.Before(now.Add(10*time.Minute)) {
		t.Fatalf("Unexpected NotBefore: wanted %s +/-10 minutes, got %s", now, cert.NotBefore)
	}
	if !cert.NotAfter.Equal(req.NotAfter) {
		t.Fatalf("Unexpected NotAfter: wanted %s, got %s", req.NotAfter, cert.NotAfter)
	}

	// custom case, NotBefore and NotAfter
	now = time.Now().UTC()
	req.NotBefore = now.Add(-time.Hour * 5).Truncate(time.Hour)
	req.NotAfter = now.Add(time.Hour * 5).Truncate(time.Hour)
	certPEM, err = s.Sign(req)
	if err != nil {
		t.Fatalf("Error signing default request: %s", err)
	}
	cert, err = helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if !cert.NotBefore.Equal(req.NotBefore) {
		t.Fatalf("Unexpected NotBefore: wanted %s, got %s", req.NotBefore, cert.NotBefore)
	}
	if !cert.NotAfter.Equal(req.NotAfter) {
		t.Fatalf("Unexpected NotAfter: wanted %s, got %s", req.NotAfter, cert.NotAfter)
	}
}

func expectOneValueOf(t *testing.T, s []string, e, n string) {
	if len(s) != 1 {
		t.Fatalf("Expected %s to have a single value, but it has %d values", n, len(s))
	}

	if s[0] != e {
		t.Fatalf("Expected %s to be '%s', but it is '%s'", n, e, s[0])
	}
}

func expectEmpty(t *testing.T, s []string, n string) {
	if len(s) != 0 {
		t.Fatalf("Expected no values in %s, but have %d values: %v", n, len(s), s)
	}
}

func TestCASignPathlen(t *testing.T) {
	var csrPathlenTests = []struct {
		name       string
		caCertFile string
		caKeyFile  string
		caProfile  bool
		csrFile    string
		err        error
		pathlen    int
		isZero     bool
		isCA       bool
	}{
		{
			name:       "pathlen 1 signing pathlen 0",
			caCertFile: testECDSACaFile,
			caKeyFile:  testECDSACaKeyFile,
			caProfile:  true,
			csrFile:    "testdata/inter_pathlen_0.csr",
			err:        nil,
			pathlen:    0,
			isZero:     true,
			isCA:       true,
		},
		{
			name:       "pathlen 1 signing pathlen 1",
			caCertFile: testECDSACaFile,
			caKeyFile:  testECDSACaKeyFile,
			caProfile:  true,
			csrFile:    "testdata/inter_pathlen_1.csr",
			err:        cferr.New(cferr.PolicyError, cferr.InvalidRequest),
		},
		{
			name:       "pathlen 0 signing pathlen 0",
			caCertFile: testCaFile,
			caKeyFile:  testCaKeyFile,
			caProfile:  true,
			csrFile:    "testdata/inter_pathlen_0.csr",
			err:        cferr.New(cferr.PolicyError, cferr.InvalidRequest),
		},
		{
			name:       "pathlen 0 signing pathlen 1",
			caCertFile: testCaFile,
			caKeyFile:  testCaKeyFile,
			caProfile:  true,
			csrFile:    "testdata/inter_pathlen_1.csr",
			err:        cferr.New(cferr.PolicyError, cferr.InvalidRequest),
		},
		{
			name:       "pathlen 0 signing pathlen unspecified",
			caCertFile: testCaFile,
			caKeyFile:  testCaKeyFile,
			caProfile:  true,
			csrFile:    "testdata/inter_pathlen_unspecified.csr",
			err:        cferr.New(cferr.PolicyError, cferr.InvalidRequest),
		},
		{
			name:       "pathlen 1 signing unspecified pathlen",
			caCertFile: testECDSACaFile,
			caKeyFile:  testECDSACaKeyFile,
			caProfile:  true,
			csrFile:    "testdata/inter_pathlen_unspecified.csr",
			err:        nil,
			// golang x509 parses unspecified pathlen as MaxPathLen == -1 and
			// MaxPathLenZero == false
			pathlen: -1,
			isZero:  false,
			isCA:    true,
		},
		{
			name:       "non-ca singing profile signing pathlen 0",
			caCertFile: testECDSACaFile,
			caKeyFile:  testECDSACaKeyFile,
			caProfile:  false,
			csrFile:    "testdata/inter_pathlen_0.csr",
			err:        cferr.New(cferr.PolicyError, cferr.InvalidRequest),
		},
		{
			name:       "non-ca singing profile signing pathlen 1",
			caCertFile: testECDSACaFile,
			caKeyFile:  testECDSACaKeyFile,
			caProfile:  false,
			csrFile:    "testdata/inter_pathlen_1.csr",
			err:        cferr.New(cferr.PolicyError, cferr.InvalidRequest),
		},
		{
			name:       "non-ca singing profile signing pathlen 0",
			caCertFile: testECDSACaFile,
			caKeyFile:  testECDSACaKeyFile,
			caProfile:  false,
			csrFile:    "testdata/inter_pathlen_unspecified.csr",
			err:        cferr.New(cferr.PolicyError, cferr.InvalidRequest),
		},
	}

	for _, testCase := range csrPathlenTests {
		csrPEM, err := os.ReadFile(testCase.csrFile)
		if err != nil {
			t.Fatalf("%v", err)
		}

		req := &signer.Subject{
			Names: []csr.Name{
				{O: "sam certificate authority"},
			},
			CN: "localhost",
		}

		s := newCustomSigner(t, testCase.caCertFile, testCase.caKeyFile)
		// No policy CSR whitelist: the normal set of CSR fields get passed through to
		// certificate.
		s.policy = &config.Signing{
			Default: &config.SigningProfile{
				Usage:        []string{"cert sign", "crl sign"},
				ExpiryString: "1h",
				Expiry:       1 * time.Hour,
				CAConstraint: config.CAConstraint{IsCA: testCase.caProfile,
					MaxPathLen:     testCase.pathlen,
					MaxPathLenZero: testCase.isZero,
				},
			},
		}

		request := signer.SignRequest{
			Hosts:   []string{"127.0.0.1", "localhost"},
			Request: string(csrPEM),
			Subject: req,
		}

		certPEM, err := s.Sign(request)
		if !reflect.DeepEqual(err, testCase.err) {
			t.Fatalf("%s: expected: %v, actual: %v", testCase.name, testCase.err, err)
		}

		if err == nil {
			cert, err := helpers.ParseCertificatePEM(certPEM)
			if err != nil {
				t.Fatalf("%s: %v", testCase.name, err)
			}

			if cert.IsCA != testCase.isCA {
				t.Fatalf("%s: unexpected IsCA value: %v", testCase.name, cert.IsCA)
			}

			if cert.MaxPathLen != testCase.pathlen {
				t.Fatalf("%s: unexpected pathlen value: %v", testCase.name, cert.MaxPathLen)
			}

			if cert.MaxPathLenZero != testCase.isZero {
				t.Fatalf("%s: unexpected pathlen value: %v", testCase.name, cert.MaxPathLenZero)
			}
		}
	}
}

func TestNoWhitelistSign(t *testing.T) {
	csrPEM, err := os.ReadFile(fullSubjectCSR)
	if err != nil {
		t.Fatalf("%v", err)
	}

	req := &signer.Subject{
		Names: []csr.Name{
			{O: "sam certificate authority"},
		},
		CN: "localhost",
	}

	s := newCustomSigner(t, testECDSACaFile, testECDSACaKeyFile)
	// No policy CSR whitelist: the normal set of CSR fields get passed through to
	// certificate.
	s.policy = &config.Signing{
		Default: &config.SigningProfile{
			Usage:        []string{"cert sign", "crl sign"},
			ExpiryString: "1h",
			Expiry:       1 * time.Hour,
			CAConstraint: config.CAConstraint{IsCA: true},
		},
	}

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

	name := cert.Subject
	if name.CommonName != "localhost" {
		t.Fatalf("Expected certificate common name to be 'localhost' but have '%v'", name.CommonName)
	}

	// CSR has: Subject: C=US, O=CloudFlare, OU=WWW, L=Ithaca, ST=New York
	// Expect all to be passed through.
	expectOneValueOf(t, name.Organization, "sam certificate authority", "O")
	expectOneValueOf(t, name.OrganizationalUnit, "WWW", "OU")
	expectOneValueOf(t, name.Province, "New York", "ST")
	expectOneValueOf(t, name.Locality, "Ithaca", "L")
	expectOneValueOf(t, name.Country, "US", "C")
}

func TestWhitelistSign(t *testing.T) {
	csrPEM, err := os.ReadFile(fullSubjectCSR)
	if err != nil {
		t.Fatalf("%v", err)
	}

	req := &signer.Subject{
		Names: []csr.Name{
			{O: "sam certificate authority"},
		},
	}

	s := newCustomSigner(t, testECDSACaFile, testECDSACaKeyFile)
	// Whitelist only key-related fields. Subject, DNSNames, etc shouldn't get
	// passed through from CSR.
	s.policy = &config.Signing{
		Default: &config.SigningProfile{
			Usage:        []string{"cert sign", "crl sign"},
			ExpiryString: "1h",
			Expiry:       1 * time.Hour,
			CAConstraint: config.CAConstraint{IsCA: true},
			CSRWhitelist: &config.CSRWhitelist{
				PublicKey:          true,
				PublicKeyAlgorithm: true,
				SignatureAlgorithm: true,
			},
		},
	}

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

	name := cert.Subject
	if name.CommonName != "" {
		t.Fatalf("Expected empty certificate common name under policy without "+
			"Subject whitelist, got %v", name.CommonName)
	}
	// O is provided by the signing API request, not the CSR, so it's allowed to
	// be copied into the certificate.
	expectOneValueOf(t, name.Organization, "sam certificate authority", "O")
	expectEmpty(t, name.OrganizationalUnit, "OU")
	expectEmpty(t, name.Province, "ST")
	expectEmpty(t, name.Locality, "L")
	expectEmpty(t, name.Country, "C")
	if cert.PublicKeyAlgorithm != x509.RSA {
		t.Fatalf("Expected public key algorithm to be RSA")
	}

	// Signature algorithm is allowed to be copied from CSR, but is overridden by
	// DefaultSigAlgo.
	if cert.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Fatalf("Expected public key algorithm to be ECDSAWithSHA256, got %v",
			cert.SignatureAlgorithm)
	}
}

func TestNameWhitelistSign(t *testing.T) {
	csrPEM, err := os.ReadFile(fullSubjectCSR)
	if err != nil {
		t.Fatalf("%v", err)
	}

	subInvalid := &signer.Subject{
		CN: "localhost.com",
	}
	subValid := &signer.Subject{
		CN: "1lab41.cf",
	}

	wl := regexp.MustCompile("^1[a-z]*[0-9]*\\.cf$")

	s := newCustomSigner(t, testECDSACaFile, testECDSACaKeyFile)
	// Whitelist only key-related fields. Subject, DNSNames, etc shouldn't get
	// passed through from CSR.
	s.policy = &config.Signing{
		Default: &config.SigningProfile{
			Usage:         []string{"cert sign", "crl sign"},
			ExpiryString:  "1h",
			Expiry:        1 * time.Hour,
			CAConstraint:  config.CAConstraint{IsCA: true},
			NameWhitelist: wl,
		},
	}

	request := signer.SignRequest{
		Hosts:   []string{"127.0.0.1", "1machine23.cf"},
		Request: string(csrPEM),
	}

	_, err = s.Sign(request)
	if err != nil {
		t.Fatalf("%v", err)
	}

	request = signer.SignRequest{
		Hosts:   []string{"invalid.cf", "1machine23.cf"},
		Request: string(csrPEM),
	}

	_, err = s.Sign(request)
	if err == nil {
		t.Fatalf("expected a policy error")
	}

	request = signer.SignRequest{
		Hosts:   []string{"1machine23.cf"},
		Request: string(csrPEM),
		Subject: subInvalid,
	}

	_, err = s.Sign(request)
	if err == nil {
		t.Fatalf("expected a policy error")
	}

	request = signer.SignRequest{
		Hosts:   []string{"1machine23.cf"},
		Request: string(csrPEM),
		Subject: subValid,
	}

	_, err = s.Sign(request)
	if err != nil {
		t.Fatalf("%v", err)
	}

}

func TestExtensionSign(t *testing.T) {
	csrPEM, err := os.ReadFile(testCSR)
	if err != nil {
		t.Fatalf("%v", err)
	}

	s := newCustomSigner(t, testECDSACaFile, testECDSACaKeyFile)

	// By default, no extensions should be allowed
	request := signer.SignRequest{
		Request: string(csrPEM),
		Extensions: []signer.Extension{
			{ID: config.OID(asn1.ObjectIdentifier{1, 2, 3, 4})},
		},
	}

	_, err = s.Sign(request)
	if err == nil {
		t.Fatalf("expected a policy error")
	}

	// Whitelist a specific extension.  The extension with OID 1.2.3.4 should be
	// allowed through, but the one with OID 1.2.3.5 should not.
	s.policy = &config.Signing{
		Default: &config.SigningProfile{
			Usage:              []string{"cert sign", "crl sign"},
			ExpiryString:       "1h",
			Expiry:             1 * time.Hour,
			CAConstraint:       config.CAConstraint{IsCA: true},
			ExtensionWhitelist: map[string]bool{"1.2.3.4": true},
		},
	}

	// Test that a forbidden extension triggers a sign error
	request = signer.SignRequest{
		Request: string(csrPEM),
		Extensions: []signer.Extension{
			{ID: config.OID(asn1.ObjectIdentifier{1, 2, 3, 5})},
		},
	}

	_, err = s.Sign(request)
	if err == nil {
		t.Fatalf("expected a policy error")
	}

	extValue := []byte{0x05, 0x00}
	extValueHex := hex.EncodeToString(extValue)

	// Test that an allowed extension makes it through
	request = signer.SignRequest{
		Request: string(csrPEM),
		Extensions: []signer.Extension{
			{
				ID:       config.OID(asn1.ObjectIdentifier{1, 2, 3, 4}),
				Critical: false,
				Value:    extValueHex,
			},
		},
	}

	certPEM, err := s.Sign(request)
	if err != nil {
		t.Fatalf("%v", err)
	}

	cert, err := helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("%v", err)
	}

	foundAllowed := false
	for _, ext := range cert.Extensions {
		if ext.Id.String() == "1.2.3.4" {
			foundAllowed = true

			if ext.Critical {
				t.Fatalf("Extensions should not be marked critical")
			}

			if !bytes.Equal(extValue, ext.Value) {
				t.Fatalf("Extension has wrong value: %s != %s", hex.EncodeToString(ext.Value), extValueHex)
			}
		}
	}
	if !foundAllowed {
		t.Fatalf("Custom extension not included in the certificate")
	}
}

func TestCTFailure(t *testing.T) {
	// start a fake CT server that returns bad request
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
	}))
	defer ts.Close()

	var config = &config.Signing{
		Default: &config.SigningProfile{
			Expiry:       helpers.OneYear,
			CAConstraint: config.CAConstraint{IsCA: true},
			Usage:        []string{"signing", "key encipherment", "server auth", "client auth"},
			ExpiryString: "8760h",
			CTLogServers: []string{ts.URL},
		},
	}
	testSigner, err := NewSignerFromFile(testCaFile, testCaKeyFile, config)
	if err != nil {
		t.Fatalf("%v", err)
	}
	var pem []byte
	pem, err = os.ReadFile("testdata/ex.csr")
	if err != nil {
		t.Fatalf("%v", err)
	}
	validReq := signer.SignRequest{
		Request: string(pem),
		Hosts:   []string{"example.com"},
	}
	_, err = testSigner.Sign(validReq)

	if err == nil {
		t.Fatal("Expected CT log submission failure")
	}
}

func TestCTSuccess(t *testing.T) {
	// start a fake CT server that will accept the submission
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"sct_version":0,"id":"KHYaGJAn++880NYaAY12sFBXKcenQRvMvfYE9F1CYVM=","timestamp":1337,"extensions":"","signature":"BAMARjBEAiAIc21J5ZbdKZHw5wLxCP+MhBEsV5+nfvGyakOIv6FOvAIgWYMZb6Pw///uiNM7QTg2Of1OqmK1GbeGuEl9VJN8v8c="}`))
		w.WriteHeader(200)
	}))
	defer ts.Close()

	var config = &config.Signing{
		Default: &config.SigningProfile{
			Expiry:       helpers.OneYear,
			CAConstraint: config.CAConstraint{IsCA: true},
			Usage:        []string{"signing", "key encipherment", "server auth", "client auth"},
			ExpiryString: "8760h",
			CTLogServers: []string{ts.URL},
		},
	}
	testSigner, err := NewSignerFromFile(testCaFile, testCaKeyFile, config)
	if err != nil {
		t.Fatalf("%v", err)
	}
	var pem []byte
	pem, err = os.ReadFile("testdata/ex.csr")
	if err != nil {
		t.Fatalf("%v", err)
	}
	validReq := signer.SignRequest{
		Request: string(pem),
		Hosts:   []string{"example.com"},
	}
	_, err = testSigner.Sign(validReq)

	if err != nil {
		t.Fatal("Expected CT log submission success")
	}
}

func TestReturnPrecert(t *testing.T) {
	var config = &config.Signing{
		Default: &config.SigningProfile{
			Expiry:       helpers.OneYear,
			CAConstraint: config.CAConstraint{IsCA: true},
			Usage:        []string{"signing", "key encipherment", "server auth", "client auth"},
			ExpiryString: "8760h",
		},
	}
	testSigner, err := NewSignerFromFile(testCaFile, testCaKeyFile, config)
	if err != nil {
		t.Fatalf("%v", err)
	}
	csr, err := os.ReadFile("testdata/ex.csr")
	if err != nil {
		t.Fatalf("%v", err)
	}
	validReq := signer.SignRequest{
		Request:       string(csr),
		Hosts:         []string{"example.com"},
		ReturnPrecert: true,
	}

	certBytes, err := testSigner.Sign(validReq)
	if err != nil {
		t.Fatal("Failed to sign request")
	}
	block, _ := pem.Decode(certBytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse signed cert: %s", err)
	}

	// check cert with poison extension was returned
	poisoned := false
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(signer.CTPoisonOID) {
			poisoned = true
			break
		}
	}
	if !poisoned {
		t.Fatal("Certificate without poison CT extension was returned")
	}
}

func TestSignFromPrecert(t *testing.T) {
	var config = &config.Signing{
		Default: &config.SigningProfile{
			Expiry:       helpers.OneYear,
			CAConstraint: config.CAConstraint{IsCA: true},
			Usage:        []string{"signing", "key encipherment", "server auth", "client auth"},
			ExpiryString: "8760h",
		},
	}
	testSigner, err := NewSignerFromFile(testCaFile, testCaKeyFile, config)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Generate a precert
	k, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("Failed to generate test key: %s", err)
	}

	_uri, _ := url.Parse("https://www.cloudflare.com")

	precertBytes, err := testSigner.sign(&x509.Certificate{
		SignatureAlgorithm: x509.SHA512WithRSA,
		PublicKey:          k.Public(),
		SerialNumber:       big.NewInt(10),
		Subject:            pkix.Name{CommonName: "CN"},
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: signer.CTPoisonOID, Critical: true, Value: []byte{0x05, 0x00}},
		},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SubjectKeyId:          []byte{0, 1},
		AuthorityKeyId:        []byte{1, 0},
		OCSPServer:            []string{"ocsp?"},
		IssuingCertificateURL: []string{"url"},
		DNSNames:              []string{"example.com"},
		EmailAddresses:        []string{"email@example.com"},
		URIs:                  []*url.URL{_uri},
		IPAddresses:           []net.IP{net.ParseIP("1.1.1.1")},
		CRLDistributionPoints: []string{"crl"},
		PolicyIdentifiers:     []asn1.ObjectIdentifier{{1, 2, 3}},
	}, 0, nil)
	if err != nil {
		t.Fatalf("Failed to sign request: %s", err)
	}
	block, _ := pem.Decode(precertBytes)
	precert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse signed cert: %s", err)
	}

	// Create a cert from the precert
	scts := []ct.SignedCertificateTimestamp{{}}
	certBytes, err := testSigner.SignFromPrecert(precert, scts)
	if err != nil {
		t.Fatalf("Failed to sign cert from precert: %s", err)
	}
	block, _ = pem.Decode(certBytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse signed cert: %s", err)
	}

	// check cert doesn't contains poison extension
	poisoned := false
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(signer.CTPoisonOID) {
			poisoned = true
			break
		}
	}
	if poisoned {
		t.Fatal("Certificate with poison CT extension was returned")
	}

	// check cert contains SCT list extension
	list := false
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(signer.SCTListOID) {
			list = true
			break
		}
	}
	if !list {
		t.Fatal("Certificate without SCT list extension was returned")
	}

	// Break poison extension
	precert.Extensions[7].Value = []byte{1, 3, 3, 7}
	_, err = testSigner.SignFromPrecert(precert, scts)
	if err == nil {
		t.Fatal("SignFromPrecert didn't fail with invalid poison extension")
	}

	precert.Extensions[7].Critical = false
	_, err = testSigner.SignFromPrecert(precert, scts)
	if err == nil {
		t.Fatal("SignFromPrecert didn't fail with non-critical poison extension")
	}

	precert.Extensions = append(precert.Extensions[:7], precert.Extensions[8:]...)
	_, err = testSigner.SignFromPrecert(precert, scts)
	if err == nil {
		t.Fatal("SignFromPrecert didn't fail with missing poison extension")
	}

	precert.Signature = []byte("nop")
	_, err = testSigner.SignFromPrecert(precert, scts)
	if err == nil {
		t.Fatal("SignFromPrecert didn't fail with signature not from CA")
	}
}

func TestLint(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial := big.NewInt(1337)

	// jankyTemplate is an x509 cert template that mostly passes through zlint
	// without errors/warnings. It is used as the basis of both the signer's issuing
	// certificate and the end entity certificate that is linted.
	jankyTemplate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "janky.cert",
		},
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, 90),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		PolicyIdentifiers: []asn1.ObjectIdentifier{
			{1, 2, 3},
		},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IssuingCertificateURL: []string{"http://ca.cpu"},
		SubjectKeyId:          []byte("⚿"),
		PublicKey:             k.Public(),
	}

	// Create a self-signed issuer certificate to use as the CA
	issuerDer, _ := x509.CreateCertificate(rand.Reader, jankyTemplate, jankyTemplate, k.Public(), k)
	issuerCert, _ := x509.ParseCertificate(issuerDer)

	lintSigner := &Signer{
		lintPriv: k,
		ca:       issuerCert,
	}

	// Reconfigure the template for an end-entity certificate.
	// On purpose this template will trip the following lints:
	//   1. e_sub_cert_aia_does_not_contain_ocsp_url because there is no OCSP URL.
	//   2. e_dnsname_not_valid_tld because `.cert` is not a real TLD
	serial = big.NewInt(1338)
	jankyTemplate.SerialNumber = serial
	jankyTemplate.Subject.CommonName = "www.janky.cert"
	jankyTemplate.DNSNames = []string{"janky.cert", "www.janky.cert"}
	jankyTemplate.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	jankyTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	jankyTemplate.IsCA = false

	ignoredLintNameRegistry, err := lint.GlobalRegistry().Filter(lint.FilterOptions{
		ExcludeNames: []string{"e_dnsname_not_valid_tld"},
	})
	if err != nil {
		t.Fatalf("failed to construct ignoredLintNamesRegistry: %v", err)
	}

	ignoredLintSourcesRegistry, err := lint.GlobalRegistry().Filter(lint.FilterOptions{
		ExcludeSources: lint.SourceList{lint.CABFBaselineRequirements},
	})
	if err != nil {
		t.Fatalf("failed to construct ignoredLintSourcesRegistry: %v", err)
	}

	testCases := []struct {
		name               string
		signer             *Signer
		lintErrLevel       lint.LintStatus
		lintRegistry       lint.Registry
		expectedErr        error
		expectedErrResults map[string]lint.LintResult
	}{
		{
			name:   "linting disabled",
			signer: lintSigner,
		},
		{
			name:         "signer without lint key",
			signer:       &Signer{},
			lintErrLevel: lint.NA,
			expectedErr:  errors.New(`{"code":2500,"message":"Private key is unavailable"}`),
		},
		{
			name:         "lint results above err level",
			signer:       lintSigner,
			lintErrLevel: lint.Notice,
			expectedErr:  errors.New("pre-issuance linting found 2 error results"),
			expectedErrResults: map[string]lint.LintResult{
				"e_sub_cert_aia_does_not_contain_ocsp_url": {Status: 6},
				"e_dnsname_not_valid_tld":                  {Status: 6},
			},
		},
		{
			name:         "lint results below err level",
			signer:       lintSigner,
			lintErrLevel: lint.Warn,
			expectedErr:  errors.New("pre-issuance linting found 2 error results"),
			expectedErrResults: map[string]lint.LintResult{
				"e_sub_cert_aia_does_not_contain_ocsp_url": {Status: 6},
				"e_dnsname_not_valid_tld":                  {Status: 6},
			},
		},
		{
			name:         "ignored lint names, lint results above err level",
			signer:       lintSigner,
			lintErrLevel: lint.Notice,
			lintRegistry: ignoredLintNameRegistry,
			expectedErr:  errors.New("pre-issuance linting found 1 error results"),
			expectedErrResults: map[string]lint.LintResult{
				"e_sub_cert_aia_does_not_contain_ocsp_url": {Status: 6},
			},
		},
		{
			name:         "ignored lint sources, lint results above err level",
			signer:       lintSigner,
			lintErrLevel: lint.Notice,
			lintRegistry: ignoredLintSourcesRegistry,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.signer.lint(*jankyTemplate, tc.lintErrLevel, tc.lintRegistry)
			if err != nil && tc.expectedErr == nil {
				t.Errorf("Expected no err, got %#v", err)
			} else if err == nil && tc.expectedErr != nil {
				t.Errorf("Expected err %v, got nil", tc.expectedErr)
			} else if err != nil && tc.expectedErr != nil {
				actual := err.Error()
				expected := tc.expectedErr.Error()
				if actual != expected {
					t.Errorf("Expected err %q got %q", expected, actual)
				}
				if len(tc.expectedErrResults) > 0 {
					le, ok := err.(*LintError)
					if !ok {
						t.Fatalf("expected LintError type err, got %v", err)
					}
					if count := len(le.ErrorResults); count != len(tc.expectedErrResults) {
						t.Fatalf("expected %d LintError results, got %d", len(tc.expectedErrResults), len(le.ErrorResults))
					}
					for name, result := range le.ErrorResults {
						if result.Status != tc.expectedErrResults[name].Status {
							t.Errorf("expected error from lint %q to have status %d not %d",
								name, tc.expectedErrResults[name].Status, result.Status)
						}
						if result.Details != tc.expectedErrResults[name].Details {
							t.Errorf("expected error from lint %q to have details %q not %q",
								name, tc.expectedErrResults[name].Details, result.Details)
						}
					}
				}
			}
		})
	}
}
