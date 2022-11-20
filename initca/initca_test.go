package initca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
)

var validKeyParams = []csr.KeyRequest{
	{A: "rsa", S: 2048},
	{A: "rsa", S: 3072},
	{A: "rsa", S: 4096},
	{A: "ecdsa", S: 256},
	{A: "ecdsa", S: 384},
	{A: "ecdsa", S: 521},
}

var validCAConfigs = []csr.CAConfig{
	{PathLength: 0, PathLenZero: true},
	{PathLength: 0, PathLenZero: false},
	{PathLength: 2},
	{PathLength: 2, Expiry: "1h"},
	// invalid PathLenZero value will be ignored
	{PathLength: 2, PathLenZero: true},
}

var invalidCAConfig = csr.CAConfig{
	PathLength: 2,
	// Expiry must be a duration string
	Expiry: "2116/12/31",
}
var csrFiles = []string{
	"testdata/rsa2048.csr",
	"testdata/rsa3072.csr",
	"testdata/rsa4096.csr",
	"testdata/ecdsa256.csr",
	"testdata/ecdsa384.csr",
	"testdata/ecdsa521.csr",
}

var testRSACAFile = "testdata/5min-rsa.pem"
var testRSACAKeyFile = "testdata/5min-rsa-key.pem"
var testECDSACAFile = "testdata/5min-ecdsa.pem"
var testECDSACAKeyFile = "testdata/5min-ecdsa-key.pem"

var invalidCryptoParams = []csr.KeyRequest{
	// Weak Key
	{A: "rsa", S: 1024},
	// Bad param
	{A: "rsaCrypto", S: 2048},
	{A: "ecdsa", S: 2000},
}

func TestInitCA(t *testing.T) {
	var req *csr.CertificateRequest
	hostname := "cloudflare.com"
	crl := "http://crl.cloudflare.com/655c6a9b-01c6-4eea-bf21-be690cc315e0.crl" // cert_uuid.crl
	for _, param := range validKeyParams {
		for _, caconfig := range validCAConfigs {
			req = &csr.CertificateRequest{
				Names: []csr.Name{
					{
						C:  "US",
						ST: "California",
						L:  "San Francisco",
						O:  "CloudFlare",
						OU: "Systems Engineering",
					},
				},
				CN:         hostname,
				Hosts:      []string{hostname, "www." + hostname},
				KeyRequest: &param,
				CA:         &caconfig,
				CRL:        crl,
			}
			certBytes, _, keyBytes, err := New(req)
			if err != nil {
				t.Fatal("InitCA failed:", err)
			}
			key, err := helpers.ParsePrivateKeyPEM(keyBytes)
			if err != nil {
				t.Fatal("InitCA private key parsing failed:", err)
			}
			cert, err := helpers.ParseCertificatePEM(certBytes)
			if err != nil {
				t.Fatal("InitCA cert parsing failed:", err)
			}

			// Verify if the CRL is set
			crlSet := false
			for _, certCrl := range cert.CRLDistributionPoints {
				if certCrl == crl {
					crlSet = true
					break
				}
			}
			if !crlSet {
				t.Fatal("Missing CRL on certificate")
			}

			// Verify key parameters.
			switch req.KeyRequest.Algo() {
			case "rsa":
				if cert.PublicKey.(*rsa.PublicKey).N.BitLen() != param.Size() {
					t.Fatal("Cert key length mismatch.")
				}
				if key.(*rsa.PrivateKey).N.BitLen() != param.Size() {
					t.Fatal("Private key length mismatch.")
				}
			case "ecdsa":
				if cert.PublicKey.(*ecdsa.PublicKey).Curve.Params().BitSize != param.Size() {
					t.Fatal("Cert key length mismatch.")
				}
				if key.(*ecdsa.PrivateKey).Curve.Params().BitSize != param.Size() {
					t.Fatal("Private key length mismatch.")
				}
			}

			// Verify CA MaxPathLen
			if caconfig.PathLength == 0 && cert.MaxPathLenZero != caconfig.PathLenZero {
				t.Fatalf("fail to init a CA cert with specified CA pathlen zero: expect %v, got %v", caconfig.PathLenZero, cert.MaxPathLenZero)
			}

			if caconfig.PathLength != 0 {
				if cert.MaxPathLen != caconfig.PathLength {
					t.Fatalf("fail to init a CA cert with specified CA pathlen: expect %d, got %d", caconfig.PathLength, cert.MaxPathLen)
				}
				if cert.MaxPathLenZero != false {
					t.Fatalf("fail to init a CA cert with specified CA pathlen zero: expect false, got %t", cert.MaxPathLenZero)
				}
			}

			// Replace the default CAPolicy with a test (short expiry) version and add a crl
			CAPolicy = func() *config.Signing {
				return &config.Signing{
					Default: &config.SigningProfile{
						Usage:        []string{"cert sign", "crl sign"},
						ExpiryString: "300s",
						Expiry:       300 * time.Second,
						CAConstraint: config.CAConstraint{IsCA: true},
						CRL:          crl,
					},
				}
			}

			// Start a signer
			s, err := local.NewSigner(key, cert, signer.DefaultSigAlgo(key), nil)
			if err != nil {
				t.Fatal("Signer Creation error:", err)
			}
			s.SetPolicy(CAPolicy())

			// Sign RSA and ECDSA customer CSRs.
			for _, csrFile := range csrFiles {
				csrBytes, err := os.ReadFile(csrFile)
				if err != nil {
					t.Fatal("CSR loading error:", err)
				}
				req := signer.SignRequest{
					Request: string(csrBytes),
					Hosts:   signer.SplitHosts(hostname),
					Profile: "",
					Label:   "",
				}

				bytes, err := s.Sign(req)
				if err != nil {
					t.Fatal(err)
				}
				customerCert, _ := helpers.ParseCertificatePEM(bytes)
				if customerCert.SignatureAlgorithm != s.SigAlgo() {
					t.Fatal("Signature Algorithm mismatch")
				}
				err = customerCert.CheckSignatureFrom(cert)
				if err != nil {
					t.Fatal("Signing CSR failed.", err)
				}
			}
		}
	}
}
func TestInvalidCAConfig(t *testing.T) {
	hostname := "example.com"
	req := &csr.CertificateRequest{
		Names: []csr.Name{
			{
				C:  "US",
				ST: "California",
				L:  "San Francisco",
				O:  "CloudFlare",
				OU: "Systems Engineering",
			},
		},
		CN:         hostname,
		Hosts:      []string{hostname, "www." + hostname},
		KeyRequest: &validKeyParams[0],
		CA:         &invalidCAConfig,
	}

	_, _, _, err := New(req)
	if err == nil {
		t.Fatal("InitCA with bad CAConfig should fail:", err)
	}
}
func TestInvalidCryptoParams(t *testing.T) {
	var req *csr.CertificateRequest
	hostname := "cloudflare.com"
	for _, invalidParam := range invalidCryptoParams {
		req = &csr.CertificateRequest{
			Names: []csr.Name{
				{
					C:  "US",
					ST: "California",
					L:  "San Francisco",
					O:  "CloudFlare",
					OU: "Systems Engineering",
				},
			},
			CN:         hostname,
			Hosts:      []string{hostname, "www." + hostname},
			KeyRequest: &invalidParam,
		}
		_, _, _, err := New(req)
		if err == nil {
			t.Fatal("InitCA with bad params should fail:", err)
		}

		if !strings.Contains(err.Error(), `"code":2400`) {
			t.Fatal(err)
		}
	}
}

type validation struct {
	r *csr.CertificateRequest
	v bool
}

var testValidations = []validation{
	{&csr.CertificateRequest{}, false},
	{&csr.CertificateRequest{
		CN: "test CA",
	}, true},
	{&csr.CertificateRequest{
		Names: []csr.Name{{}},
	}, false},
	{&csr.CertificateRequest{
		Names: []csr.Name{
			{O: "Example CA"},
		},
	}, true},
}

func TestValidations(t *testing.T) {
	for i, tv := range testValidations {
		err := validator(tv.r)
		if tv.v && err != nil {
			t.Fatalf("%v", err)
		}

		if !tv.v && err == nil {
			t.Fatalf("%d: expected error, but no error was reported", i)
		}
	}
}

func TestRenewRSA(t *testing.T) {
	certPEM, err := RenewFromPEM(testRSACAFile, testRSACAKeyFile)
	if err != nil {
		t.Fatal(err)
	}

	// must parse ok
	cert, err := helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}

	if !cert.IsCA {
		t.Fatal("renewed CA certificate is not CA")
	}

	// cert expiry must be 5 minutes
	expiry := cert.NotAfter.Sub(cert.NotBefore).Seconds()
	if expiry >= 301 || expiry <= 299 {
		t.Fatal("expiry is not correct:", expiry)
	}

	// check subject

	if cert.Subject.CommonName != "" {
		t.Fatal("Bad CommonName")
	}

	if len(cert.Subject.Country) != 1 || cert.Subject.Country[0] != "US" {
		t.Fatal("Bad Subject")
	}

	if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != "CloudFlare, Inc." {
		t.Fatal("Bad Subject")
	}
}

func TestRenewECDSA(t *testing.T) {
	certPEM, err := RenewFromPEM(testECDSACAFile, testECDSACAKeyFile)
	if err != nil {
		t.Fatal(err)
	}

	// must parse ok
	cert, err := helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}

	if !cert.IsCA {
		t.Fatal("renewed CA certificate is not CA")
	}

	// cert expiry must be 5 minutes
	expiry := cert.NotAfter.Sub(cert.NotBefore).Seconds()
	if expiry >= 301 || expiry <= 299 {
		t.Fatal("expiry is not correct:", expiry)
	}

	// check subject

	if cert.Subject.CommonName != "" {
		t.Fatal("Bad CommonName")
	}

	if len(cert.Subject.Country) != 1 || cert.Subject.Country[0] != "US" {
		t.Fatal("Bad Subject")
	}

	if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != "CloudFlare, Inc." {
		t.Fatal("Bad Subject")
	}
}

func TestRenewMismatch(t *testing.T) {
	_, err := RenewFromPEM(testECDSACAFile, testRSACAKeyFile)
	if err == nil {
		t.Fatal("Fail to detect cert/key mismatch")
	}
}

func TestRenew(t *testing.T) {
	in, err := os.ReadFile(testECDSACAFile)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := helpers.ParseCertificatePEM(in)
	if err != nil {
		t.Fatal(err)
	}

	in, err = os.ReadFile(testECDSACAKeyFile)
	if err != nil {
		t.Fatal(err)
	}

	priv, err := helpers.ParsePrivateKeyPEM(in)
	if err != nil {
		t.Fatal(err)
	}

	renewed, err := Update(cert, priv)
	if err != nil {
		t.Fatal(err)
	}

	newCert, err := helpers.ParseCertificatePEM(renewed)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(newCert.RawSubjectPublicKeyInfo, cert.RawSubjectPublicKeyInfo) {
		t.Fatal("Update returned a certificate with different subject public key info")
	}

	if !bytes.Equal(newCert.RawSubject, cert.RawSubject) {
		t.Fatal("Update returned a certificate with different subject info")
	}

	if !bytes.Equal(newCert.RawIssuer, cert.RawIssuer) {
		t.Fatal("Update returned a certificate with different issuer info")
	}
}
