package local

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/signer"
)

const tagRelativeOID = 13

// relativeOIDSubject returns a Name whose single attribute has a RELATIVE-OID
// value, which pkix.Name cannot represent.
func relativeOIDSubject(t *testing.T) []byte {
	t.Helper()
	name := pkix.RDNSequence{{{
		Type:  asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 25, 3},
		Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: tagRelativeOID, Bytes: []byte{0x82, 0xda, 0x4b, 0x31, 0x01, 0x01}},
	}}}
	der, err := asn1.Marshal(name)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func rawSubjectCSR(t *testing.T, rawSubject []byte) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		RawSubject:         rawSubject,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func whitelistPolicy(whitelist *config.CSRWhitelist) *config.Signing {
	return &config.Signing{Default: &config.SigningProfile{
		Usage:        []string{"digital signature"},
		ExpiryString: "1h",
		Expiry:       time.Hour,
		CSRWhitelist: whitelist,
	}}
}

func TestSignPreservesRawSubject(t *testing.T) {
	raw := relativeOIDSubject(t)
	tests := []struct {
		name      string
		whitelist *config.CSRWhitelist
		subject   *signer.Subject
		wantRaw   bool
		wantO     string
	}{
		{
			name:    "no whitelist",
			wantRaw: true,
		},
		{
			name: "subject whitelisted",
			whitelist: &config.CSRWhitelist{
				Subject: true, PublicKey: true, PublicKeyAlgorithm: true, SignatureAlgorithm: true,
			},
			wantRaw: true,
		},
		{
			name: "subject not whitelisted",
			whitelist: &config.CSRWhitelist{
				PublicKey: true, PublicKeyAlgorithm: true, SignatureAlgorithm: true,
			},
		},
		{
			name:    "request subject overrides raw subject",
			subject: &signer.Subject{Names: []csr.Name{{O: "override"}}},
			wantO:   "override",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestSigner(t)
			s.policy = whitelistPolicy(tt.whitelist)

			certPEM, err := s.Sign(signer.SignRequest{Request: rawSubjectCSR(t, raw), Subject: tt.subject})
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}
			cert, err := helpers.ParseCertificatePEM(certPEM)
			if err != nil {
				t.Fatal(err)
			}

			if got := bytes.Equal(cert.RawSubject, raw); got != tt.wantRaw {
				t.Errorf("subject equals the CSR subject = %t, want %t (subject % x)", got, tt.wantRaw, cert.RawSubject)
			}
			if tt.wantO != "" {
				if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != tt.wantO {
					t.Errorf("Organization = %v, want [%s]", cert.Subject.Organization, tt.wantO)
				}
			}
			if !tt.wantRaw && bytes.Contains(cert.RawSubject, []byte{tagRelativeOID}) {
				t.Errorf("subject still carries the RELATIVE-OID attribute")
			}
		})
	}
}

func TestSignRegularSubjectIsUnchanged(t *testing.T) {
	s := newTestSigner(t)
	s.policy = whitelistPolicy(nil)

	req, err := (&csr.CertificateRequest{CN: "example.com", Names: []csr.Name{{O: "Org", C: "US"}}}).Name()
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := s.Sign(signer.SignRequest{Request: rawSubjectCSR(t, mustMarshalName(t, req))})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	cert, err := helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "example.com" || len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != "Org" {
		t.Errorf("Subject = %v", cert.Subject)
	}
}

func mustMarshalName(t *testing.T, name pkix.Name) []byte {
	t.Helper()
	der, err := asn1.Marshal(name.ToRDNSequence())
	if err != nil {
		t.Fatal(err)
	}
	return der
}
