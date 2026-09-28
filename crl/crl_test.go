package crl

import (
	"crypto/x509"
	"os"
	"testing"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/initca"
)

const (
	serverCertFile = "testdata/ca.pem"
	serverKeyFile  = "testdata/ca-key.pem"
	tryTwoCert     = "testdata/caTwo.pem"
	tryTwoKey      = "testdata/ca-keyTwo.pem"
	serialList     = "testdata/serialList"
)

func TestNewCRLFromFile(t *testing.T) {

	tryTwoKeyBytes, err := os.ReadFile(tryTwoKey)
	if err != nil {
		t.Fatal(err)
	}

	tryTwoCertBytes, err := os.ReadFile(tryTwoCert)
	if err != nil {
		t.Fatal(err)
	}

	serialListBytes, err := os.ReadFile(serialList)
	if err != nil {
		t.Fatal(err)
	}

	crl, err := NewCRLFromFile(serialListBytes, tryTwoCertBytes, tryTwoKeyBytes, "0")
	if err != nil {
		t.Fatal(err)
	}

	certList, err := x509.ParseDERCRL(crl)
	if err != nil {
		t.Fatal(err)
	}

	numCerts := len(certList.TBSCertList.RevokedCertificates)
	expectedNum := 4
	if expectedNum != numCerts {
		t.Fatal("Wrong number of expired certificates")
	}
}

func TestNewCRLFromFileWithoutRevocations(t *testing.T) {
	tryTwoKeyBytes, err := os.ReadFile(tryTwoKey)
	if err != nil {
		t.Fatal(err)
	}

	tryTwoCertBytes, err := os.ReadFile(tryTwoCert)
	if err != nil {
		t.Fatal(err)
	}

	crl, err := NewCRLFromFile([]byte("\n \n"), tryTwoCertBytes, tryTwoKeyBytes, "0")
	if err != nil {
		t.Fatal(err)
	}

	certList, err := x509.ParseDERCRL(crl)
	if err != nil {
		t.Fatal(err)
	}

	numCerts := len(certList.TBSCertList.RevokedCertificates)
	expectedNum := 0
	if expectedNum != numCerts {
		t.Fatal("Wrong number of expired certificates")
	}
}

func TestNewCRLFromFileMLDSA(t *testing.T) {
	tests := []struct {
		algo   string
		sigAlg x509.SignatureAlgorithm
	}{
		{algo: "mldsa44", sigAlg: x509.MLDSA44},
		{algo: "mldsa65", sigAlg: x509.MLDSA65},
		{algo: "mldsa87", sigAlg: x509.MLDSA87},
	}

	for _, tt := range tests {
		t.Run(tt.algo, func(t *testing.T) {
			req := &csr.CertificateRequest{
				CN:         "ML-DSA test CA",
				KeyRequest: &csr.KeyRequest{A: tt.algo},
			}
			certPEM, _, keyPEM, err := initca.New(req)
			if err != nil {
				t.Fatalf("creating CA: %v", err)
			}

			crlDER, err := NewCRLFromFile([]byte("1\n"), certPEM, keyPEM, "60")
			if err != nil {
				t.Fatalf("creating CRL: %v", err)
			}

			parsedCRL, err := x509.ParseRevocationList(crlDER)
			if err != nil {
				t.Fatalf("parsing CRL: %v", err)
			}
			if parsedCRL.SignatureAlgorithm != tt.sigAlg {
				t.Fatalf("signature algorithm = %v, want %v", parsedCRL.SignatureAlgorithm, tt.sigAlg)
			}
			if len(parsedCRL.RevokedCertificateEntries) != 1 {
				t.Fatalf("revoked certificate count = %d, want 1", len(parsedCRL.RevokedCertificateEntries))
			}

			issuer, err := helpers.ParseCertificatePEM(certPEM)
			if err != nil {
				t.Fatalf("parsing CA: %v", err)
			}
			if err := parsedCRL.CheckSignatureFrom(issuer); err != nil {
				t.Fatalf("checking CRL signature: %v", err)
			}
		})
	}
}
