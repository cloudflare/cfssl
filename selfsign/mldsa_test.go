package selfsign

import (
	"crypto/mldsa"
	"crypto/x509"
	"errors"
	"reflect"
	"testing"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/helpers"
)

// TestSignMLDSADefaultProfileKeyUsage verifies that a self-signed ML-DSA
// certificate issued under the default profile does not carry
// keyEncipherment, which RFC 9881 prohibits for ML-DSA subject keys.
func TestSignMLDSADefaultProfileKeyUsage(t *testing.T) {
	tests := []struct {
		name   string
		params mldsa.Parameters
	}{
		{"MLDSA44", mldsa.MLDSA44()},
		{"MLDSA65", mldsa.MLDSA65()},
		{"MLDSA87", mldsa.MLDSA87()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			priv, err := mldsa.GenerateKey(tt.params)
			if err != nil {
				t.Fatalf("generating ML-DSA key: %v", err)
			}
			csrPEM, err := csr.Generate(priv, &csr.CertificateRequest{
				CN:    "mldsa.example.com",
				Hosts: []string{"mldsa.example.com"},
			})
			if err != nil {
				t.Fatalf("generating CSR: %v", err)
			}

			certPEM, err := Sign(priv, csrPEM, config.DefaultConfig())
			if err != nil {
				t.Fatalf("Sign() failed: %v", err)
			}
			cert, err := helpers.ParseCertificatePEM(certPEM)
			if err != nil {
				t.Fatalf("parsing certificate: %v", err)
			}

			if cert.KeyUsage != x509.KeyUsageDigitalSignature {
				t.Errorf("KeyUsage = %#b, want %#b (digitalSignature only)", cert.KeyUsage, x509.KeyUsageDigitalSignature)
			}
			wantEKU := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
			if !reflect.DeepEqual(cert.ExtKeyUsage, wantEKU) {
				t.Errorf("ExtKeyUsage = %v, want %v", cert.ExtKeyUsage, wantEKU)
			}
		})
	}
}

// TestSignMLDSAOnlyForbiddenKeyUsagesWithEKU verifies that a profile whose key
// usages are all prohibited for ML-DSA is rejected even when it also lists
// extended key usages, instead of producing a certificate without a keyUsage
// extension.
func TestSignMLDSAOnlyForbiddenKeyUsagesWithEKU(t *testing.T) {
	priv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatalf("generating ML-DSA key: %v", err)
	}
	csrPEM, err := csr.Generate(priv, &csr.CertificateRequest{
		CN:    "mldsa.example.com",
		Hosts: []string{"mldsa.example.com"},
	})
	if err != nil {
		t.Fatalf("generating CSR: %v", err)
	}
	noKeyUsagesCode := cferr.New(cferr.PolicyError, cferr.NoKeyUsages).ErrorCode

	tests := []struct {
		name  string
		usage []string
		isCA  bool
	}{
		{"KeyEnciphermentServerAuth", []string{"key encipherment", "server auth"}, false},
		{"KeyAgreementClientAuth", []string{"key agreement", "client auth"}, false},
		{"SMIMEEncryption", []string{"key encipherment", "data encipherment", "email protection"}, false},
		{"CAKeyEnciphermentServerAuth", []string{"key encipherment", "server auth"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := config.DefaultConfig()
			profile.Usage = tt.usage
			profile.CAConstraint.IsCA = tt.isCA

			certPEM, err := Sign(priv, csrPEM, profile)
			var cfErr *cferr.Error
			if !errors.As(err, &cfErr) || cfErr.ErrorCode != noKeyUsagesCode {
				t.Fatalf("Sign() = (%d bytes, %v), want NoKeyUsages policy error (code %d)", len(certPEM), err, noKeyUsagesCode)
			}
		})
	}
}
