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
	"regexp"
	"strings"
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

// rdn returns a DER SET of the given attribute type and value.
func rdn(t *testing.T, attributeType asn1.ObjectIdentifier, value asn1.RawValue) []byte {
	t.Helper()
	atv, err := asn1.Marshal(struct {
		Type  asn1.ObjectIdentifier
		Value asn1.RawValue
	}{attributeType, value})
	if err != nil {
		t.Fatal(err)
	}
	set, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: atv})
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func name(t *testing.T, rdns ...[]byte) []byte {
	t.Helper()
	der, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: bytes.Join(rdns, nil)})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func stringValue(tag int, s string) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: tag, Bytes: []byte(s)}
}

var (
	oidCN = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidO  = asn1.ObjectIdentifier{2, 5, 4, 10}
)

func TestNameWhitelistChecksEveryRawSubjectCommonName(t *testing.T) {
	allowed := rdn(t, oidCN, stringValue(asn1.TagUTF8String, "allowed.example"))
	evil := rdn(t, oidCN, stringValue(asn1.TagUTF8String, "evil.example"))
	org := rdn(t, oidO, stringValue(asn1.TagUTF8String, "Org"))

	multiValued, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true,
		Bytes: append(rdn(t, oidCN, stringValue(asn1.TagUTF8String, "evil.example"))[2:], rdn(t, oidCN, stringValue(asn1.TagUTF8String, "allowed.example"))[2:]...)})
	if err != nil {
		t.Fatal(err)
	}
	octetString := rdn(t, oidCN, asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagOctetString, Bytes: []byte("evil.example")})

	tests := []struct {
		name    string
		subject []byte
		wantErr bool
	}{
		{"one allowed CN", name(t, allowed, org), false},
		{"extra CN before the allowed one", name(t, evil, org, allowed), true},
		{"extra CN after the allowed one", name(t, allowed, org, evil), true},
		{"multi-valued RDN with a disallowed CN", name(t, multiValued), true},
		{"CN that is not a string", name(t, octetString), true},
		{"no CN", name(t, org), false},
		{"TAI subject", relativeOIDSubject(t), false},
	}
	modes := []struct {
		name      string
		whitelist *config.CSRWhitelist
	}{
		{"no CSR whitelist", nil},
		{"subject whitelisted", &config.CSRWhitelist{Subject: true, PublicKey: true, PublicKeyAlgorithm: true, SignatureAlgorithm: true}},
	}
	for _, mode := range modes {
		whitelist := mode.whitelist
		for _, tt := range tests {
			t.Run(mode.name+"/"+tt.name, func(t *testing.T) {
				s := newTestSigner(t)
				s.policy = whitelistPolicy(whitelist)
				s.policy.Default.NameWhitelist = regexp.MustCompile(`^allowed\.example$`)
				s.policy.Default.KeepCSRSubject = true

				_, err := s.Sign(signer.SignRequest{Hosts: []string{"allowed.example"}, Request: rawSubjectCSR(t, tt.subject)})
				if tt.wantErr {
					if err == nil || !strings.Contains(err.Error(), `"code":5500`) {
						t.Errorf("Sign() error = %v, want code 5500", err)
					}
					return
				}
				if err != nil {
					t.Errorf("Sign() error = %v", err)
				}
			})
		}
	}
}

func TestSignKeepsSubjectBytesOnlyWhenNeeded(t *testing.T) {
	// A UTF8String CN first, which the decoded form would re-encode as
	// a PrintableString.
	utf8First := name(t,
		rdn(t, oidCN, stringValue(asn1.TagUTF8String, "device1")),
		rdn(t, oidO, stringValue(asn1.TagUTF8String, "Acme")),
	)
	tests := []struct {
		name     string
		subject  []byte
		keep     bool
		wantSame bool
	}{
		{"representable, default profile", utf8First, false, false},
		{"representable, profile keeps the CSR subject", utf8First, true, true},
		{"not representable, default profile", relativeOIDSubject(t), false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestSigner(t)
			s.policy = whitelistPolicy(nil)
			s.policy.Default.KeepCSRSubject = tt.keep

			certPEM, err := s.Sign(signer.SignRequest{Request: rawSubjectCSR(t, tt.subject)})
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}
			cert, err := helpers.ParseCertificatePEM(certPEM)
			if err != nil {
				t.Fatal(err)
			}
			if got := bytes.Equal(cert.RawSubject, tt.subject); got != tt.wantSame {
				t.Errorf("subject equals the CSR subject = %t, want %t", got, tt.wantSame)
			}
			if cert.Subject.CommonName != "device1" && bytes.Equal(tt.subject, utf8First) {
				t.Errorf("CommonName = %q, want device1", cert.Subject.CommonName)
			}
		})
	}
}

// An attribute value that encoding/asn1 decodes to nil, other than a
// RELATIVE-OID, is not copied into the certificate when the profile does not
// keep the CSR subject. On a common attribute it is dropped, as on master. On
// another attribute encoding fails, as on master.
func TestSignDropsUndecodableAttributeValues(t *testing.T) {
	cn := rdn(t, oidCN, stringValue(asn1.TagUTF8String, "device1"))
	org := rdn(t, oidO, stringValue(asn1.TagUTF8String, "Acme"))
	universal := asn1.RawValue{Class: asn1.ClassUniversal, Tag: 28, Bytes: []byte{0, 0, 0, 'E'}}
	universalOrg := rdn(t, oidO, universal)
	universalOther := rdn(t, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, universal)
	taiSet := rdn(t, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 25, 3}, asn1.RawValue{Class: asn1.ClassUniversal, Tag: tagRelativeOID, Bytes: []byte{0x82, 0xda, 0x4b, 0x31, 0x01, 0x01}})
	universalDER := []byte{28, 4, 0, 0, 0, 'E'}

	for _, tt := range []struct {
		name    string
		subject []byte
		wantErr bool
		wantTAI bool
	}{
		{"common attribute", name(t, cn, org, universalOrg), false, false},
		{"common attribute next to a RELATIVE-OID", name(t, cn, org, universalOrg, taiSet), false, true},
		{"other attribute", name(t, cn, universalOther), true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestSigner(t)
			s.policy = whitelistPolicy(nil)
			certPEM, err := s.Sign(signer.SignRequest{Request: rawSubjectCSR(t, tt.subject)})
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Sign() = %d bytes, want an error", len(certPEM))
				}
				return
			}
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}
			cert, err := helpers.ParseCertificatePEM(certPEM)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(cert.RawSubject, universalDER) {
				t.Error("the UniversalString value was copied into the subject")
			}
			if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != "Acme" {
				t.Errorf("Organization = %v, want [Acme]", cert.Subject.Organization)
			}
			if got := bytes.Contains(cert.RawSubject, []byte{tagRelativeOID, 6, 0x82, 0xda, 0x4b, 0x31, 0x01, 0x01}); got != tt.wantTAI {
				t.Errorf("subject has the RELATIVE-OID value = %t, want %t", got, tt.wantTAI)
			}
		})
	}
}

// A subject with a RELATIVE-OID attribute and a common name, without
// KeepCSRSubject, is encoded from its decoded form with the RELATIVE-OID value
// as encoded.
func TestSignRestoresRelativeOIDValue(t *testing.T) {
	cn := rdn(t, oidCN, stringValue(asn1.TagUTF8String, "device1"))
	taiSet := rdn(t, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 25, 3}, asn1.RawValue{Class: asn1.ClassUniversal, Tag: tagRelativeOID, Bytes: []byte{0x82, 0xda, 0x4b, 0x31, 0x01, 0x01}})
	subject := name(t, cn, taiSet)

	s := newTestSigner(t)
	s.policy = whitelistPolicy(nil)
	certPEM, err := s.Sign(signer.SignRequest{Request: rawSubjectCSR(t, subject)})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	cert, err := helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "device1" {
		t.Errorf("CommonName = %q, want device1", cert.Subject.CommonName)
	}
	if !bytes.Contains(cert.RawSubject, []byte{tagRelativeOID, 6, 0x82, 0xda, 0x4b, 0x31, 0x01, 0x01}) {
		t.Errorf("RELATIVE-OID value not encoded in the subject: % x", cert.RawSubject)
	}
}
