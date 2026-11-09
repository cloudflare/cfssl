package initca

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/signer"
)

var (
	_ func(*csr.CertificateRequest, []byte) ([]byte, []byte, error)        = NewUnsigned
	_ func(*csr.CertificateRequest, []byte, crypto.Signer) ([]byte, error) = NewUnsignedFromSigner
)

// defaultCAPolicy is CAPolicy as initialised by the package. TestInitCA
// replaces CAPolicy without restoring it, so tests that depend on the default
// policy reinstate it with useCAPolicy.
var defaultCAPolicy = CAPolicy

const (
	codeCertificateUnknown = 1000
	codeReadFailed         = 1001
	codeParseFailed        = 1003
	codePrivateKeyUnknown  = 2000
	codeEncrypted          = 2100
	codeKeyMismatch        = 2300
	codeGenerationFailed   = 2400
	codeKeyUnavailable     = 2500
	codeNoKeyUsages        = 5100
	codeInvalidPolicy      = 5200
	codeInvalidRequest     = 5300

	// tagRelativeOID is the universal tag of RELATIVE-OID (X.690, Section 8.20).
	tagRelativeOID = 13

	testCommonName = "unsigned test"
	testCRL        = "http://crl.example.com/unsigned-root.crl"
	testOCSP       = "http://ocsp.example.com"
	testIssuerURL  = "http://ca.example.com/root.crt"
	leafDNSName    = "leaf.example.com"
	maxSerialBits  = 159
)

var (
	// idRDNATrustAnchorID is id-rdna-trustAnchorID.
	idRDNATrustAnchorID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 25, 3}
	trustAnchorArcs     = []uint32{44363, 49, 1, 1}

	// unsignedAlgorithmDER is AlgorithmIdentifier{id-alg-unsigned} with the
	// parameters absent.
	unsignedAlgorithmDER = []byte{0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x24}
	// emptySignatureDER is a BIT STRING with no bits.
	emptySignatureDER = []byte{0x03, 0x01, 0x00}

	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidSubjectAltName   = asn1.ObjectIdentifier{2, 5, 29, 17}

	errInjected = errors.New("injected failure")
)

var unsignedKeyAlgorithms = []struct {
	name    string
	request csr.KeyRequest
	pemType string
}{
	{"ecdsa-256", csr.KeyRequest{A: "ecdsa", S: 256}, "EC PRIVATE KEY"},
	{"ecdsa-384", csr.KeyRequest{A: "ecdsa", S: 384}, "EC PRIVATE KEY"},
	{"ecdsa-521", csr.KeyRequest{A: "ecdsa", S: 521}, "EC PRIVATE KEY"},
	{"rsa-2048", csr.KeyRequest{A: "rsa", S: 2048}, "RSA PRIVATE KEY"},
	{"ed25519", csr.KeyRequest{A: "ed25519"}, "Ed25519 PRIVATE KEY"},
	{"mldsa44", csr.KeyRequest{A: "mldsa44"}, "PRIVATE KEY"},
	{"mldsa65", csr.KeyRequest{A: "mldsa65"}, "PRIVATE KEY"},
	{"mldsa87", csr.KeyRequest{A: "mldsa87"}, "PRIVATE KEY"},
}

// certificateDER is the outer structure of an X.509 certificate.
type certificateDER struct {
	TBS       asn1.RawValue
	Algorithm asn1.RawValue
	Signature asn1.RawValue
}

// mismatchedSigner signs with its embedded key but reports public as its
// public key.
type mismatchedSigner struct {
	crypto.Signer
	public crypto.PublicKey
}

func (s mismatchedSigner) Public() crypto.PublicKey {
	return s.public
}

// swappingSigner signs with its embedded key but reports decoy as its public
// key until it is asked to sign, and the embedded key's public key after.
type swappingSigner struct {
	crypto.Signer
	decoy  crypto.PublicKey
	signed bool
}

func (s *swappingSigner) Public() crypto.PublicKey {
	if s.signed {
		return s.Signer.Public()
	}
	return s.decoy
}

func (s *swappingSigner) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.signed = true
	return s.Signer.Sign(random, digest, opts)
}

func (s *swappingSigner) SignMessage(random io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.signed = true
	return crypto.SignMessage(s.Signer, random, msg, opts)
}

// failingSigner reports the public key of its embedded key but fails to sign
// with err.
type failingSigner struct {
	crypto.Signer
	err error
}

func (s failingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, s.err
}

// zeroReader is a random source that only produces zero bytes.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// errorReader is a random source that fails with err.
type errorReader struct {
	err error
}

func (r errorReader) Read([]byte) (int, error) {
	return 0, r.err
}

type unsignedRoot struct {
	cert    *x509.Certificate
	keyType string
	priv    crypto.Signer
}

// encodeRelativeOID returns the content octets of a RELATIVE-OID with the
// given arcs: each arc in base 128, most significant group first, with the
// high bit set on every group but the last (X.690, Section 8.20.2).
func encodeRelativeOID(arcs ...uint32) []byte {
	var out []byte
	for _, arc := range arcs {
		groups := []byte{byte(arc & 0x7f)}
		for arc >>= 7; arc > 0; arc >>= 7 {
			groups = append(groups, byte(arc&0x7f)|0x80)
		}
		slices.Reverse(groups)
		out = append(out, groups...)
	}
	return out
}

// taiName returns the DER Name with a single id-rdna-trustAnchorID attribute
// whose value is the RELATIVE-OID with the given arcs.
func taiName(t *testing.T, arcs ...uint32) []byte {
	t.Helper()
	name := pkix.RDNSequence{{{
		Type:  idRDNATrustAnchorID,
		Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: tagRelativeOID, Bytes: encodeRelativeOID(arcs...)},
	}}}
	der, err := asn1.Marshal(name)
	if err != nil {
		t.Fatalf("marshaling trust anchor ID name: %v", err)
	}
	return der
}

// commonNameDER returns the DER Name with only the common name cn.
func commonNameDER(t *testing.T, cn string) []byte {
	t.Helper()
	der, err := asn1.Marshal(pkix.Name{CommonName: cn}.ToRDNSequence())
	if err != nil {
		t.Fatalf("marshaling common name: %v", err)
	}
	return der
}

func useCAPolicy(t *testing.T, policy func() *config.Signing) {
	t.Helper()
	saved := CAPolicy
	CAPolicy = policy
	t.Cleanup(func() { CAPolicy = saved })
}

func requireErrorCode(t *testing.T, err error, code int) {
	t.Helper()
	if err == nil {
		t.Fatalf("got no error, want code %d", code)
	}
	if want := fmt.Sprintf(`"code":%d`, code); !strings.Contains(err.Error(), want) {
		t.Fatalf("got error %v, want code %d", err, code)
	}
}

func parseSingleCertificatePEM(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, rest := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		t.Fatalf("got %q, want exactly one CERTIFICATE PEM block", certPEM)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("x509.ParseCertificate() error = %v", err)
	}
	return cert
}

func mustNewUnsigned(t *testing.T, req *csr.CertificateRequest, rawSubject []byte) unsignedRoot {
	t.Helper()
	certPEM, keyPEM, err := NewUnsigned(req, rawSubject)
	if err != nil {
		t.Fatalf("NewUnsigned() error = %v", err)
	}
	cert := parseSingleCertificatePEM(t, certPEM)
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		t.Fatalf("NewUnsigned() returned key %q, want PEM", keyPEM)
	}
	priv, err := helpers.ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		t.Fatalf("helpers.ParsePrivateKeyPEM() error = %v", err)
	}
	return unsignedRoot{cert: cert, keyType: keyBlock.Type, priv: priv}
}

func mustNewUnsignedFromSigner(t *testing.T, req *csr.CertificateRequest, rawSubject []byte, priv crypto.Signer) *x509.Certificate {
	t.Helper()
	certPEM, err := NewUnsignedFromSigner(req, rawSubject, priv)
	if err != nil {
		t.Fatalf("NewUnsignedFromSigner() error = %v", err)
	}
	return parseSingleCertificatePEM(t, certPEM)
}

func generateSigner(t *testing.T, request csr.KeyRequest) crypto.Signer {
	t.Helper()
	priv, err := request.Generate()
	if err != nil {
		t.Fatalf("generating %s key: %v", request.Algo(), err)
	}
	return priv.(crypto.Signer)
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	key, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && key.Equal(b)
}

// decodeFields returns the DER elements that make up contents.
func decodeFields(t *testing.T, contents []byte) []asn1.RawValue {
	t.Helper()
	var fields []asn1.RawValue
	for rest := contents; len(rest) > 0; {
		var field asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &field); err != nil {
			t.Fatalf("decoding field %d: %v", len(fields), err)
		}
		fields = append(fields, field)
	}
	return fields
}

// sequence returns the DER SEQUENCE of the given encoded elements.
func sequence(t *testing.T, elements ...[]byte) []byte {
	t.Helper()
	der, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: bytes.Join(elements, nil)})
	if err != nil {
		t.Fatalf("marshaling SEQUENCE: %v", err)
	}
	return der
}

func selfSignedECDSACertificate(t *testing.T) []byte {
	t.Helper()
	priv := generateSigner(t, csr.KeyRequest{A: "ecdsa", S: 256})
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: testCommonName},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() error = %v", err)
	}
	return der
}

func TestEncodeRelativeOID_MatchesGoldenBytes(t *testing.T) {
	tests := []struct {
		name string
		arcs []uint32
		want []byte
	}{
		{"trust anchor ID 44363.49.1.1", []uint32{44363, 49, 1, 1}, []byte{0x82, 0xda, 0x4b, 0x31, 0x01, 0x01}},
		{"zero middle group 32768", []uint32{32768}, []byte{0x82, 0x80, 0x00}},
		{"two groups 128", []uint32{128}, []byte{0x81, 0x00}},
		{"largest single group 127", []uint32{127}, []byte{0x7f}},
		{"zero arc", []uint32{0}, []byte{0x00}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := encodeRelativeOID(tt.arcs...); !bytes.Equal(got, tt.want) {
				t.Errorf("encodeRelativeOID(%v) = % x, want % x", tt.arcs, got, tt.want)
			}
		})
	}
}

func TestTAIName_MatchesGoldenBytes(t *testing.T) {
	want := []byte{
		0x30, 0x16, 0x31, 0x14, 0x30, 0x12,
		0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x19, 0x03,
		0x0d, 0x06, 0x82, 0xda, 0x4b, 0x31, 0x01, 0x01,
	}
	if got := taiName(t, trustAnchorArcs...); !bytes.Equal(got, want) {
		t.Errorf("taiName(%v) = % x, want % x", trustAnchorArcs, got, want)
	}
}

func TestNewUnsigned_UsesRawNameVerbatimForEveryKeyAlgorithm(t *testing.T) {
	useCAPolicy(t, defaultCAPolicy)
	names := []struct {
		name       string
		rawSubject []byte
		wantCN     string
	}{
		{"trust anchor ID name", taiName(t, trustAnchorArcs...), ""},
		{"common name", commonNameDER(t, testCommonName), testCommonName},
	}
	for _, alg := range unsignedKeyAlgorithms {
		for _, name := range names {
			t.Run(alg.name+"/"+name.name, func(t *testing.T) {
				keyRequest := alg.request
				root := mustNewUnsigned(t, &csr.CertificateRequest{KeyRequest: &keyRequest}, name.rawSubject)
				if !bytes.Equal(root.cert.RawSubject, name.rawSubject) {
					t.Errorf("RawSubject = % x, want % x", root.cert.RawSubject, name.rawSubject)
				}
				if !bytes.Equal(root.cert.RawIssuer, name.rawSubject) {
					t.Errorf("RawIssuer = % x, want % x", root.cert.RawIssuer, name.rawSubject)
				}
				if root.cert.Subject.CommonName != name.wantCN {
					t.Errorf("Subject.CommonName = %q, want %q", root.cert.Subject.CommonName, name.wantCN)
				}
			})
		}
	}
}

func TestNewUnsigned_EncodesUnsignedSignature(t *testing.T) {
	useCAPolicy(t, defaultCAPolicy)
	rawSubject := taiName(t, trustAnchorArcs...)
	for _, alg := range unsignedKeyAlgorithms {
		t.Run(alg.name, func(t *testing.T) {
			keyRequest := alg.request
			root := mustNewUnsigned(t, &csr.CertificateRequest{KeyRequest: &keyRequest}, rawSubject)

			var decoded certificateDER
			rest, err := asn1.Unmarshal(root.cert.Raw, &decoded)
			if err != nil {
				t.Fatalf("decoding certificate: %v", err)
			}
			if len(rest) != 0 {
				t.Fatalf("certificate has %d trailing bytes", len(rest))
			}
			if !bytes.Equal(decoded.Algorithm.FullBytes, unsignedAlgorithmDER) {
				t.Errorf("signatureAlgorithm = % x, want % x", decoded.Algorithm.FullBytes, unsignedAlgorithmDER)
			}
			if !bytes.Equal(decoded.Signature.FullBytes, emptySignatureDER) {
				t.Errorf("signatureValue = % x, want % x", decoded.Signature.FullBytes, emptySignatureDER)
			}
			var signature asn1.BitString
			if _, err := asn1.Unmarshal(decoded.Signature.FullBytes, &signature); err != nil {
				t.Fatalf("decoding signatureValue: %v", err)
			}
			if signature.BitLength != 0 || len(signature.Bytes) != 0 {
				t.Errorf("signatureValue has %d bits, want 0", signature.BitLength)
			}

			fields := decodeFields(t, decoded.TBS.Bytes)
			const wantFields = 8 // version through extensions, no unique IDs
			if len(fields) != wantFields {
				t.Fatalf("TBSCertificate has %d fields, want %d", len(fields), wantFields)
			}
			if version := fields[0]; version.Class != asn1.ClassContextSpecific || version.Tag != 0 || !version.IsCompound {
				t.Errorf("TBSCertificate field 0 = % x, want [0] EXPLICIT version", version.FullBytes)
			}
			if serial := fields[1]; serial.Class != asn1.ClassUniversal || serial.Tag != asn1.TagInteger {
				t.Errorf("TBSCertificate field 1 = % x, want INTEGER serialNumber", serial.FullBytes)
			}
			if !bytes.Equal(fields[2].FullBytes, decoded.Algorithm.FullBytes) {
				t.Errorf("TBSCertificate signature = % x, want signatureAlgorithm % x", fields[2].FullBytes, decoded.Algorithm.FullBytes)
			}
			if !bytes.Equal(fields[3].FullBytes, rawSubject) {
				t.Errorf("TBSCertificate issuer = % x, want % x", fields[3].FullBytes, rawSubject)
			}
			if !bytes.Equal(fields[5].FullBytes, rawSubject) {
				t.Errorf("TBSCertificate subject = % x, want % x", fields[5].FullBytes, rawSubject)
			}

			if len(root.cert.Signature) != 0 {
				t.Errorf("parsed Signature has %d bytes, want 0", len(root.cert.Signature))
			}
			if root.cert.SignatureAlgorithm != x509.UnknownSignatureAlgorithm {
				t.Errorf("parsed SignatureAlgorithm = %v, want UnknownSignatureAlgorithm", root.cert.SignatureAlgorithm)
			}
			if !helpers.IsUnsigned(root.cert) {
				t.Error("helpers.IsUnsigned() = false, want true")
			}
		})
	}
}

func TestNewUnsigned_IssuesCACertificateWithoutHosts(t *testing.T) {
	useCAPolicy(t, defaultCAPolicy)
	rawSubject := taiName(t, trustAnchorArcs...)
	hosts := []string{"cloudflare.com", "192.0.2.1", "admin@example.com", "https://example.com/ca"}
	for _, alg := range unsignedKeyAlgorithms {
		t.Run(alg.name, func(t *testing.T) {
			keyRequest := alg.request
			root := mustNewUnsigned(t, &csr.CertificateRequest{KeyRequest: &keyRequest, Hosts: hosts}, rawSubject)
			cert := root.cert

			if !cert.IsCA || !cert.BasicConstraintsValid {
				t.Errorf("IsCA = %t, BasicConstraintsValid = %t, want both true", cert.IsCA, cert.BasicConstraintsValid)
			}
			basicConstraintsCritical := false
			for _, ext := range cert.Extensions {
				if ext.Id.Equal(oidBasicConstraints) {
					basicConstraintsCritical = ext.Critical
				}
				if ext.Id.Equal(oidSubjectAltName) {
					t.Errorf("certificate has a subjectAltName extension")
				}
			}
			if !basicConstraintsCritical {
				t.Errorf("basicConstraints extension is missing or not critical")
			}
			if want := x509.KeyUsageCertSign | x509.KeyUsageCRLSign; cert.KeyUsage != want {
				t.Errorf("KeyUsage = %v, want %v", cert.KeyUsage, want)
			}
			if len(cert.AuthorityKeyId) != 0 {
				t.Errorf("AuthorityKeyId = % x, want none", cert.AuthorityKeyId)
			}
			wantSKI, err := signer.ComputeSKI(&x509.Certificate{PublicKey: root.priv.Public()})
			if err != nil {
				t.Fatalf("signer.ComputeSKI() error = %v", err)
			}
			if !bytes.Equal(cert.SubjectKeyId, wantSKI) {
				t.Errorf("SubjectKeyId = % x, want % x", cert.SubjectKeyId, wantSKI)
			}
			if len(cert.DNSNames) != 0 || len(cert.IPAddresses) != 0 || len(cert.EmailAddresses) != 0 || len(cert.URIs) != 0 {
				t.Errorf("certificate has SANs %v %v %v %v, want none", cert.DNSNames, cert.IPAddresses, cert.EmailAddresses, cert.URIs)
			}
		})
	}
}

func TestNewUnsigned_ReturnsMatchingKeyPair(t *testing.T) {
	useCAPolicy(t, defaultCAPolicy)
	rawSubject := taiName(t, trustAnchorArcs...)
	for _, alg := range unsignedKeyAlgorithms {
		t.Run(alg.name, func(t *testing.T) {
			keyRequest := alg.request
			root := mustNewUnsigned(t, &csr.CertificateRequest{KeyRequest: &keyRequest}, rawSubject)

			if !publicKeysEqual(root.priv.Public(), root.cert.PublicKey) {
				t.Errorf("certificate public key does not match the returned private key")
			}
			if root.keyType != alg.pemType {
				t.Errorf("key PEM type = %q, want %q", root.keyType, alg.pemType)
			}

			parseRequestKeyRequest := alg.request
			_, parseRequestKey, err := csr.ParseRequest(&csr.CertificateRequest{CN: testCommonName, KeyRequest: &parseRequestKeyRequest})
			if err != nil {
				t.Fatalf("csr.ParseRequest() error = %v", err)
			}
			if block, _ := pem.Decode(parseRequestKey); block == nil || block.Type != root.keyType {
				t.Errorf("key PEM type = %q, want the csr.ParseRequest type %v", root.keyType, block)
			}
		})
	}
}

func TestNewUnsigned_RootVerifiesLeaf(t *testing.T) {
	useCAPolicy(t, defaultCAPolicy)
	rawSubject := taiName(t, trustAnchorArcs...)
	tests := []struct {
		name    string
		request csr.KeyRequest
	}{
		{"ecdsa-256", csr.KeyRequest{A: "ecdsa", S: 256}},
		{"mldsa44", csr.KeyRequest{A: "mldsa44"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := mustNewUnsigned(t, &csr.CertificateRequest{KeyRequest: &tt.request}, rawSubject)

			leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("generating leaf key: %v", err)
			}
			leafTemplate := &x509.Certificate{
				SerialNumber: big.NewInt(2),
				Subject:      pkix.Name{CommonName: leafDNSName},
				DNSNames:     []string{leafDNSName},
				NotBefore:    time.Now().Add(-time.Minute),
				NotAfter:     time.Now().Add(time.Hour),
				KeyUsage:     x509.KeyUsageDigitalSignature,
				ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}
			leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root.cert, &leafKey.PublicKey, root.priv)
			if err != nil {
				t.Fatalf("x509.CreateCertificate(leaf) error = %v", err)
			}
			leaf, err := x509.ParseCertificate(leafDER)
			if err != nil {
				t.Fatalf("x509.ParseCertificate(leaf) error = %v", err)
			}

			roots := x509.NewCertPool()
			roots.AddCert(root.cert)
			chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: leafDNSName})
			if err != nil {
				t.Fatalf("leaf.Verify() error = %v", err)
			}
			if anchor := chains[0][len(chains[0])-1]; !anchor.Equal(root.cert) {
				t.Errorf("chain ends at %v, want the unsigned root", anchor.Subject)
			}
			if err := leaf.CheckSignatureFrom(root.cert); err != nil {
				t.Errorf("leaf.CheckSignatureFrom(root) error = %v", err)
			}
		})
	}
}

func TestNewUnsigned_GeneratesDistinctPositiveSerials(t *testing.T) {
	useCAPolicy(t, defaultCAPolicy)
	rawSubject := taiName(t, trustAnchorArcs...)
	var serials []*big.Int
	for range 2 {
		root := mustNewUnsigned(t, &csr.CertificateRequest{}, rawSubject)
		serial := root.cert.SerialNumber
		if serial.Sign() <= 0 {
			t.Errorf("serial %v is not positive", serial)
		}
		if serial.BitLen() > maxSerialBits {
			t.Errorf("serial has %d bits, want at most %d", serial.BitLen(), maxSerialBits)
		}
		serials = append(serials, serial)
	}
	if serials[0].Cmp(serials[1]) == 0 {
		t.Errorf("two calls produced the same serial %v", serials[0])
	}
}

func TestNewUnsigned_AppliesValidityPeriod(t *testing.T) {
	useCAPolicy(t, defaultCAPolicy)
	rawSubject := taiName(t, trustAnchorArcs...)
	tests := []struct {
		name         string
		ca           *csr.CAConfig
		wantValidity time.Duration
		wantBackdate time.Duration
	}{
		{"default CA policy", nil, 43800 * time.Hour, 5 * time.Minute},
		{"CA expiry and backdate", &csr.CAConfig{Expiry: "1h", Backdate: "10m"}, time.Hour, 10 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := time.Now()
			root := mustNewUnsigned(t, &csr.CertificateRequest{CA: tt.ca}, rawSubject)
			after := time.Now()

			if got := root.cert.NotAfter.Sub(root.cert.NotBefore); got != tt.wantValidity {
				t.Errorf("validity = %v, want %v", got, tt.wantValidity)
			}
			notBefore := root.cert.NotBefore
			earliest := before.Round(time.Minute).Add(-tt.wantBackdate)
			latest := after.Round(time.Minute).Add(-tt.wantBackdate)
			if notBefore.Before(earliest) || notBefore.After(latest) {
				t.Errorf("NotBefore = %v, want between %v and %v", notBefore, earliest, latest)
			}
			if !notBefore.Equal(notBefore.Truncate(time.Minute)) {
				t.Errorf("NotBefore = %v, want a whole minute", notBefore)
			}
		})
	}
}

func TestNewUnsigned_RejectsInvalidCAConfig(t *testing.T) {
	useCAPolicy(t, defaultCAPolicy)
	rawSubject := taiName(t, trustAnchorArcs...)
	tests := []struct {
		name string
		ca   csr.CAConfig
	}{
		{"expiry is a date", invalidCAConfig},
		{"backdate is not a duration", csr.CAConfig{Backdate: "yesterday"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, key, err := NewUnsigned(&csr.CertificateRequest{CA: &tt.ca}, rawSubject)
			requireErrorCode(t, err, codeInvalidRequest)
			if cert != nil || key != nil {
				t.Errorf("got cert %q and key %q, want nil", cert, key)
			}
		})
	}
}

func TestNewUnsigned_PathLength(t *testing.T) {
	useCAPolicy(t, defaultCAPolicy)
	rawSubject := taiName(t, trustAnchorArcs...)
	tests := []struct {
		name               string
		ca                 csr.CAConfig
		wantMaxPathLen     int
		wantMaxPathLenZero bool
	}{
		{"pathlen 0 with pathlenzero", csr.CAConfig{PathLength: 0, PathLenZero: true}, 0, true},
		{"pathlen 0 without pathlenzero is unlimited", csr.CAConfig{PathLength: 0, PathLenZero: false}, -1, false},
		{"pathlen 2", csr.CAConfig{PathLength: 2}, 2, false},
		{"pathlen 2 ignores pathlenzero", csr.CAConfig{PathLength: 2, PathLenZero: true}, 2, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := mustNewUnsigned(t, &csr.CertificateRequest{CA: &tt.ca}, rawSubject)
			if root.cert.MaxPathLen != tt.wantMaxPathLen || root.cert.MaxPathLenZero != tt.wantMaxPathLenZero {
				t.Errorf("MaxPathLen = %d, MaxPathLenZero = %t, want %d, %t",
					root.cert.MaxPathLen, root.cert.MaxPathLenZero, tt.wantMaxPathLen, tt.wantMaxPathLenZero)
			}
		})
	}
}

func TestNewUnsigned_PathLengthMatchesNew(t *testing.T) {
	useCAPolicy(t, defaultCAPolicy)
	rawSubject := taiName(t, trustAnchorArcs...)
	for _, caConfig := range validCAConfigs {
		t.Run(fmt.Sprintf("%+v", caConfig), func(t *testing.T) {
			signedPEM, _, _, err := New(&csr.CertificateRequest{CN: testCommonName, CA: &caConfig})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			signed := parseSingleCertificatePEM(t, signedPEM)
			unsigned := mustNewUnsigned(t, &csr.CertificateRequest{CA: &caConfig}, rawSubject).cert

			if unsigned.MaxPathLen != signed.MaxPathLen || unsigned.MaxPathLenZero != signed.MaxPathLenZero {
				t.Errorf("MaxPathLen = %d, MaxPathLenZero = %t, want New's %d, %t",
					unsigned.MaxPathLen, unsigned.MaxPathLenZero, signed.MaxPathLen, signed.MaxPathLenZero)
			}
			if unsigned.IsCA != signed.IsCA || unsigned.BasicConstraintsValid != signed.BasicConstraintsValid {
				t.Errorf("IsCA = %t, BasicConstraintsValid = %t, want New's %t, %t",
					unsigned.IsCA, unsigned.BasicConstraintsValid, signed.IsCA, signed.BasicConstraintsValid)
			}
		})
	}
}

func TestNewUnsigned_CRLDistributionPoint(t *testing.T) {
	useCAPolicy(t, defaultCAPolicy)
	rawSubject := taiName(t, trustAnchorArcs...)
	tests := []struct {
		name string
		crl  string
		want []string
	}{
		{"CRL set", testCRL, []string{testCRL}},
		{"CRL empty", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := mustNewUnsigned(t, &csr.CertificateRequest{CRL: tt.crl}, rawSubject)
			if !slices.Equal(root.cert.CRLDistributionPoints, tt.want) {
				t.Errorf("CRLDistributionPoints = %q, want %q", root.cert.CRLDistributionPoints, tt.want)
			}
		})
	}
}

func TestNewUnsigned_RejectsSubjectFields(t *testing.T) {
	useCAPolicy(t, defaultCAPolicy)
	rawSubject := taiName(t, trustAnchorArcs...)
	priv := generateSigner(t, csr.KeyRequest{A: "ecdsa", S: 256})
	tests := []struct {
		name string
		req  *csr.CertificateRequest
	}{
		{"nil request", nil},
		{"common name", &csr.CertificateRequest{CN: testCommonName}},
		{"names", &csr.CertificateRequest{Names: []csr.Name{{O: "Example"}}}},
		{"empty name entry", &csr.CertificateRequest{Names: []csr.Name{{}}}},
		{"serial number", &csr.CertificateRequest{SerialNumber: "1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, key, err := NewUnsigned(tt.req, rawSubject)
			requireErrorCode(t, err, codeInvalidRequest)
			if cert != nil || key != nil {
				t.Errorf("NewUnsigned() returned cert %q and key %q, want nil", cert, key)
			}

			cert, err = NewUnsignedFromSigner(tt.req, rawSubject, priv)
			requireErrorCode(t, err, codeInvalidRequest)
			if cert != nil {
				t.Errorf("NewUnsignedFromSigner() returned cert %q, want nil", cert)
			}
		})
	}
}

func TestNewUnsigned_RejectsInvalidRawName(t *testing.T) {
	useCAPolicy(t, defaultCAPolicy)
	priv := generateSigner(t, csr.KeyRequest{A: "ecdsa", S: 256})
	valid := commonNameDER(t, testCommonName)
	nonMinimalLength := append([]byte{valid[0], 0x81}, valid[1:]...)
	const (
		notSequence  = "not a single DER SEQUENCE"
		notSet       = "RelativeDistinguishedName is not a SET"
		notOneValue  = "does not have exactly one value"
		notAttribute = "AttributeTypeAndValue is not a SEQUENCE"
	)
	tests := []struct {
		name       string
		rawSubject []byte
		wantDetail string
	}{
		{"nil", nil, notSequence},
		{"empty", []byte{}, notSequence},
		{"empty RDNSequence", []byte{0x30, 0x00}, "empty RDNSequence"},
		{"trailing byte after name", append(slices.Clone(valid), 0x00), notSequence},
		{"truncated name", valid[:len(valid)-1], notSequence},
		{"top level OCTET STRING", []byte{0x04, 0x02, 0x00, 0x00}, notSequence},
		{"non-minimal length", nonMinimalLength, notSequence},
		{"indefinite length", []byte{0x30, 0x80, 0x31, 0x00, 0x00, 0x00}, notSequence},
		{"RDNSequence holds a non-SET", []byte{0x30, 0x02, 0x04, 0x00}, notSet},
		{"trailing byte inside RDNSequence", sequence(t, valid[2:], []byte{0x00}), notSet},
		{"empty SET", []byte{0x30, 0x02, 0x31, 0x00}, "empty RelativeDistinguishedName"},
		{"SET holds a non-SEQUENCE", []byte{0x30, 0x04, 0x31, 0x02, 0x04, 0x00}, notAttribute},
		{"attribute without value", []byte{0x30, 0x09, 0x31, 0x07, 0x30, 0x05, 0x06, 0x03, 0x55, 0x04, 0x03}, notOneValue},
		{"attribute type is not an OID", []byte{0x30, 0x0b, 0x31, 0x09, 0x30, 0x07, 0x04, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x00}, "attribute type is not an OBJECT IDENTIFIER"},
		{"attribute with two values", []byte{0x30, 0x0d, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x00, 0x0c, 0x00}, notOneValue},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, key, err := NewUnsigned(&csr.CertificateRequest{}, tt.rawSubject)
			requireErrorCode(t, err, codeInvalidRequest)
			if !strings.Contains(err.Error(), tt.wantDetail) {
				t.Errorf("got error %v, want detail %q", err, tt.wantDetail)
			}
			if cert != nil || key != nil {
				t.Errorf("NewUnsigned() returned cert %q and key %q, want nil", cert, key)
			}

			cert, err = NewUnsignedFromSigner(&csr.CertificateRequest{}, tt.rawSubject, priv)
			requireErrorCode(t, err, codeInvalidRequest)
			if !strings.Contains(err.Error(), tt.wantDetail) {
				t.Errorf("got error %v, want detail %q", err, tt.wantDetail)
			}
			if cert != nil {
				t.Errorf("NewUnsignedFromSigner() returned cert %q, want nil", cert)
			}
		})
	}
}

func TestNewUnsignedFromSigner_RejectsMismatchedKey(t *testing.T) {
	useCAPolicy(t, defaultCAPolicy)
	rawSubject := taiName(t, trustAnchorArcs...)
	signers := []struct {
		name string
		wrap func(priv crypto.Signer, other crypto.PublicKey) crypto.Signer
	}{
		{"reports another key", func(priv crypto.Signer, other crypto.PublicKey) crypto.Signer {
			return mismatchedSigner{Signer: priv, public: other}
		}},
		{"reports another key until it signs", func(priv crypto.Signer, other crypto.PublicKey) crypto.Signer {
			return &swappingSigner{Signer: priv, decoy: other}
		}},
	}
	for _, request := range []csr.KeyRequest{{A: "ecdsa", S: 256}, {A: "ed25519"}, {A: "mldsa44"}, {A: "rsa", S: 2048}} {
		for _, s := range signers {
			t.Run(request.Algo()+"/"+s.name, func(t *testing.T) {
				priv := s.wrap(generateSigner(t, request), generateSigner(t, request).Public())
				cert, err := NewUnsignedFromSigner(&csr.CertificateRequest{}, rawSubject, priv)
				requireErrorCode(t, err, codeKeyMismatch)
				if cert != nil {
					t.Errorf("returned cert %q, want nil", cert)
				}
			})
		}
	}
}

func TestNewUnsignedFromSigner_ReportsSignerErrors(t *testing.T) {
	useCAPolicy(t, defaultCAPolicy)
	rawSubject := taiName(t, trustAnchorArcs...)
	ecdhKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating ECDH key: %v", err)
	}
	ecdsaKey := generateSigner(t, csr.KeyRequest{A: "ecdsa", S: 256})
	tests := []struct {
		name     string
		priv     crypto.Signer
		wantCode int
	}{
		{"nil signer", nil, codePrivateKeyUnknown},
		{"signer fails to sign", failingSigner{Signer: ecdsaKey, err: errInjected}, codeCertificateUnknown},
		{"unsupported public key type", mismatchedSigner{Signer: ecdsaKey, public: ecdhKey.PublicKey()}, codeKeyUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := NewUnsignedFromSigner(&csr.CertificateRequest{}, rawSubject, tt.priv)
			requireErrorCode(t, err, tt.wantCode)
			if cert != nil {
				t.Errorf("returned cert %q, want nil", cert)
			}
		})
	}
}

func TestNewUnsignedFromSigner_ReturnsSignerCFSSLErrorUnchanged(t *testing.T) {
	useCAPolicy(t, defaultCAPolicy)
	rawSubject := taiName(t, trustAnchorArcs...)
	ecdsaKey := generateSigner(t, csr.KeyRequest{A: "ecdsa", S: 256})
	signerErr := cferr.New(cferr.PrivateKeyError, cferr.Encrypted)
	tests := []struct {
		name string
		err  error
	}{
		{"CFSSL error", signerErr},
		{"wrapped CFSSL error", fmt.Errorf("hardware signer: %w", signerErr)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := NewUnsignedFromSigner(&csr.CertificateRequest{}, rawSubject, failingSigner{Signer: ecdsaKey, err: tt.err})
			var got *cferr.Error
			if !errors.As(err, &got) || got != signerErr {
				t.Errorf("got error %v, want the signer's error %v", err, signerErr)
			}
			if cert != nil {
				t.Errorf("returned cert %q, want nil", cert)
			}
		})
	}
}

func TestNewUnsigned_RejectsInvalidKeyRequest(t *testing.T) {
	useCAPolicy(t, defaultCAPolicy)
	rawSubject := taiName(t, trustAnchorArcs...)
	for _, request := range invalidCryptoParams {
		t.Run(fmt.Sprintf("%s-%d", request.Algo(), request.Size()), func(t *testing.T) {
			cert, key, err := NewUnsigned(&csr.CertificateRequest{KeyRequest: &request}, rawSubject)
			requireErrorCode(t, err, codeGenerationFailed)
			if cert != nil || key != nil {
				t.Errorf("returned cert %q and key %q, want nil", cert, key)
			}
		})
	}
}

func TestNewUnsigned_DefaultsToECDSAP256(t *testing.T) {
	useCAPolicy(t, defaultCAPolicy)
	root := mustNewUnsigned(t, &csr.CertificateRequest{}, taiName(t, trustAnchorArcs...))
	pub, ok := root.cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		t.Errorf("certificate public key is %T, want an ECDSA P-256 key", root.cert.PublicKey)
	}
	if root.keyType != "EC PRIVATE KEY" {
		t.Errorf("key PEM type = %q, want %q", root.keyType, "EC PRIVATE KEY")
	}
}

func TestNewUnsignedFromSigner_IgnoresKeyRequest(t *testing.T) {
	useCAPolicy(t, defaultCAPolicy)
	priv := generateSigner(t, csr.KeyRequest{A: "ecdsa", S: 256})
	req := &csr.CertificateRequest{KeyRequest: &csr.KeyRequest{A: "rsa", S: 2048}}
	cert := mustNewUnsignedFromSigner(t, req, taiName(t, trustAnchorArcs...), priv)
	if _, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok {
		t.Errorf("certificate public key is %T, want *ecdsa.PublicKey", cert.PublicKey)
	}
	if !publicKeysEqual(priv.Public(), cert.PublicKey) {
		t.Errorf("certificate public key does not match the signer")
	}
}

func TestNewUnsigned_AppliesPolicyExtKeyUsages(t *testing.T) {
	useCAPolicy(t, func() *config.Signing {
		return &config.Signing{Default: &config.SigningProfile{
			Usage:        []string{"cert sign", "crl sign", "server auth", "client auth"},
			Expiry:       time.Hour,
			CAConstraint: config.CAConstraint{IsCA: true},
		}}
	})
	want := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}

	root := mustNewUnsigned(t, &csr.CertificateRequest{}, taiName(t, trustAnchorArcs...))
	if !slices.Equal(root.cert.ExtKeyUsage, want) {
		t.Errorf("ExtKeyUsage = %v, want %v", root.cert.ExtKeyUsage, want)
	}
	if wantKU := x509.KeyUsageCertSign | x509.KeyUsageCRLSign; root.cert.KeyUsage != wantKU {
		t.Errorf("KeyUsage = %v, want %v", root.cert.KeyUsage, wantKU)
	}

	signedPEM, _, _, err := New(&csr.CertificateRequest{CN: testCommonName})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if signed := parseSingleCertificatePEM(t, signedPEM); !slices.Equal(root.cert.ExtKeyUsage, signed.ExtKeyUsage) {
		t.Errorf("ExtKeyUsage = %v, want New's %v", root.cert.ExtKeyUsage, signed.ExtKeyUsage)
	}
}

func TestNewUnsigned_ProfileFieldsMatchNew(t *testing.T) {
	notBefore := time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(24 * time.Hour)
	policyOID, err := x509.ParseOID("1.3.6.1.4.1.44947.1.1.1")
	if err != nil {
		t.Fatalf("x509.ParseOID() error = %v", err)
	}
	useCAPolicy(t, func() *config.Signing {
		return &config.Signing{Default: &config.SigningProfile{
			Usage:        []string{"cert sign", "crl sign"},
			Expiry:       time.Hour,
			CAConstraint: config.CAConstraint{IsCA: true},
			NotBefore:    notBefore,
			NotAfter:     notAfter,
			OCSP:         testOCSP,
			IssuerURL:    []string{testIssuerURL},
			CRL:          testCRL,
			Policies:     []config.CertificatePolicy{{ID: config.OID{1, 3, 6, 1, 4, 1, 44947, 1, 1, 1}}},
		}}
	})

	unsigned := mustNewUnsigned(t, &csr.CertificateRequest{}, taiName(t, trustAnchorArcs...)).cert
	signedPEM, _, _, err := New(&csr.CertificateRequest{CN: testCommonName})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	signed := parseSingleCertificatePEM(t, signedPEM)

	tests := []struct {
		name  string
		field func(*x509.Certificate) string
		want  string
	}{
		{"NotBefore", func(c *x509.Certificate) string { return c.NotBefore.String() }, notBefore.String()},
		{"NotAfter", func(c *x509.Certificate) string { return c.NotAfter.String() }, notAfter.String()},
		{"OCSPServer", func(c *x509.Certificate) string { return fmt.Sprint(c.OCSPServer) }, fmt.Sprint([]string{testOCSP})},
		{"IssuingCertificateURL", func(c *x509.Certificate) string { return fmt.Sprint(c.IssuingCertificateURL) }, fmt.Sprint([]string{testIssuerURL})},
		{"CRLDistributionPoints", func(c *x509.Certificate) string { return fmt.Sprint(c.CRLDistributionPoints) }, fmt.Sprint([]string{testCRL})},
		{"Policies", func(c *x509.Certificate) string { return fmt.Sprint(c.Policies) }, fmt.Sprint([]x509.OID{policyOID})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.field(unsigned); got != tt.want {
				t.Errorf("%s = %s, want %s", tt.name, got, tt.want)
			}
			if got, fromNew := tt.field(unsigned), tt.field(signed); got != fromNew {
				t.Errorf("%s = %s, want New's %s", tt.name, got, fromNew)
			}
		})
	}
}

func TestNewUnsigned_ValidatesPolicyAfterApplyingCAConfig(t *testing.T) {
	rawSubject := taiName(t, trustAnchorArcs...)
	withoutExpiry := func() *config.Signing {
		return &config.Signing{Default: &config.SigningProfile{
			Usage:        []string{"cert sign", "crl sign"},
			CAConstraint: config.CAConstraint{IsCA: true},
		}}
	}
	tests := []struct {
		name         string
		policy       func() *config.Signing
		ca           csr.CAConfig
		wantCode     int
		wantValidity time.Duration
	}{
		{"CA expiry of zero invalidates the policy", defaultCAPolicy, csr.CAConfig{Expiry: "0s"}, codeInvalidPolicy, 0},
		{"CA expiry completes a policy without expiry", withoutExpiry, csr.CAConfig{Expiry: "1h"}, 0, time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useCAPolicy(t, tt.policy)
			certPEM, keyPEM, err := NewUnsigned(&csr.CertificateRequest{CA: &tt.ca}, rawSubject)
			signedPEM, _, _, newErr := New(&csr.CertificateRequest{CN: testCommonName, CA: &tt.ca})
			if tt.wantCode != 0 {
				requireErrorCode(t, err, tt.wantCode)
				if certPEM != nil || keyPEM != nil {
					t.Errorf("returned cert %q and key %q, want nil", certPEM, keyPEM)
				}
				requireErrorCode(t, newErr, tt.wantCode)
				return
			}

			if err != nil {
				t.Fatalf("NewUnsigned() error = %v", err)
			}
			if newErr != nil {
				t.Fatalf("New() error = %v", newErr)
			}
			unsigned := parseSingleCertificatePEM(t, certPEM)
			if got := unsigned.NotAfter.Sub(unsigned.NotBefore); got != tt.wantValidity {
				t.Errorf("validity = %v, want %v", got, tt.wantValidity)
			}
			signed := parseSingleCertificatePEM(t, signedPEM)
			if got := signed.NotAfter.Sub(signed.NotBefore); got != tt.wantValidity {
				t.Errorf("New's validity = %v, want %v", got, tt.wantValidity)
			}
		})
	}
}

func TestNewUnsigned_RejectsUnusableCAPolicy(t *testing.T) {
	rawSubject := taiName(t, trustAnchorArcs...)
	// sameAsNew marks the cases where New fails with the same code. For a nil
	// policy, New falls back to the local signer's default configuration.
	tests := []struct {
		name      string
		policy    *config.Signing
		request   csr.KeyRequest
		wantCode  int
		sameAsNew bool
	}{
		{name: "nil policy", request: csr.KeyRequest{A: "ecdsa", S: 256}, wantCode: codeInvalidPolicy},
		{
			name:      "nil default profile",
			policy:    &config.Signing{},
			request:   csr.KeyRequest{A: "ecdsa", S: 256},
			wantCode:  codeInvalidPolicy,
			sameAsNew: true,
		},
		{
			name: "no key usage valid for ML-DSA",
			policy: &config.Signing{Default: &config.SigningProfile{
				Usage:        []string{"key encipherment"},
				Expiry:       time.Hour,
				CAConstraint: config.CAConstraint{IsCA: true},
			}},
			request:   csr.KeyRequest{A: "mldsa44"},
			wantCode:  codeNoKeyUsages,
			sameAsNew: true,
		},
		{
			name: "no key usage valid for ML-DSA despite extended key usage",
			policy: &config.Signing{Default: &config.SigningProfile{
				Usage:        []string{"key encipherment", "server auth"},
				Expiry:       time.Hour,
				CAConstraint: config.CAConstraint{IsCA: true},
			}},
			request:   csr.KeyRequest{A: "mldsa44"},
			wantCode:  codeNoKeyUsages,
			sameAsNew: true,
		},
		{
			name: "default profile without expiry",
			policy: &config.Signing{Default: &config.SigningProfile{
				Usage:        []string{"cert sign", "crl sign"},
				CAConstraint: config.CAConstraint{IsCA: true},
			}},
			request:   csr.KeyRequest{A: "ecdsa", S: 256},
			wantCode:  codeInvalidPolicy,
			sameAsNew: true,
		},
		{
			name: "profile does not issue CA certificates",
			policy: &config.Signing{Default: &config.SigningProfile{
				Usage:  []string{"cert sign", "crl sign"},
				Expiry: time.Hour,
			}},
			request:   csr.KeyRequest{A: "ecdsa", S: 256},
			wantCode:  codeInvalidRequest,
			sameAsNew: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useCAPolicy(t, func() *config.Signing { return tt.policy })
			cert, key, err := NewUnsigned(&csr.CertificateRequest{KeyRequest: &tt.request}, rawSubject)
			requireErrorCode(t, err, tt.wantCode)
			if cert != nil || key != nil {
				t.Errorf("returned cert %q and key %q, want nil", cert, key)
			}

			if tt.sameAsNew {
				_, _, _, err := New(&csr.CertificateRequest{CN: testCommonName, KeyRequest: &tt.request})
				requireErrorCode(t, err, tt.wantCode)
			}
		})
	}
}

func TestCheckPossession(t *testing.T) {
	valid := selfSignedECDSACertificate(t)
	corrupted := slices.Clone(valid)
	corrupted[len(corrupted)-1] ^= 0xff
	tests := []struct {
		name     string
		der      []byte
		wantCode int
	}{
		{"valid self-signature", valid, 0},
		{"signature does not verify", corrupted, codeKeyMismatch},
		{"not a certificate", []byte{0x30, 0x00}, codeParseFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkPossession(tt.der)
			if tt.wantCode == 0 {
				if err != nil {
					t.Fatalf("checkPossession() error = %v", err)
				}
				return
			}
			requireErrorCode(t, err, tt.wantCode)
		})
	}
}

func TestRandomSerialNumber(t *testing.T) {
	zeroSerial := make([]byte, serialNumberLength)
	topBitOnly := append([]byte{0x80}, make([]byte, serialNumberLength-1)...)
	allOnes := bytes.Repeat([]byte{0xff}, serialNumberLength)
	maxSerial := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), maxSerialBits), big.NewInt(1))
	readerErr := cferr.New(cferr.CertificateError, cferr.ReadFailed)
	tests := []struct {
		name     string
		random   io.Reader
		want     *big.Int
		wantCode int
	}{
		{"top bit cleared", bytes.NewReader(allOnes), maxSerial, 0},
		{"zero serial drawn again", io.MultiReader(bytes.NewReader(zeroSerial), bytes.NewReader(allOnes)), maxSerial, 0},
		{"serial zero after clearing top bit drawn again", io.MultiReader(bytes.NewReader(topBitOnly), bytes.NewReader(allOnes)), maxSerial, 0},
		{"random source produces only zeros", zeroReader{}, nil, codeCertificateUnknown},
		{"random source fails", errorReader{err: errInjected}, nil, codeCertificateUnknown},
		{"random source fails with CFSSL error", errorReader{err: readerErr}, nil, codeReadFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := randomSerialNumber(tt.random)
			if tt.wantCode != 0 {
				requireErrorCode(t, err, tt.wantCode)
				if got != nil {
					t.Errorf("randomSerialNumber() = %v, want nil", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("randomSerialNumber() error = %v", err)
			}
			if got.Cmp(tt.want) != 0 {
				t.Errorf("randomSerialNumber() = %x, want %x", got, tt.want)
			}
		})
	}
}

func TestWrapError(t *testing.T) {
	cfsslErr := cferr.New(cferr.PrivateKeyError, cferr.Encrypted)
	tests := []struct {
		name     string
		err      error
		wantCode int
		wantSame bool
	}{
		{"plain error is wrapped", errInjected, codeCertificateUnknown, false},
		{"CFSSL error is returned unchanged", cfsslErr, codeEncrypted, true},
		{"wrapped CFSSL error is unwrapped", fmt.Errorf("context: %w", cfsslErr), codeEncrypted, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := wrapError(cferr.CertificateError, cferr.Unknown, tt.err)
			requireErrorCode(t, err, tt.wantCode)
			if same := err == error(cfsslErr); same != tt.wantSame {
				t.Errorf("wrapError() returned the CFSSL error itself = %t, want %t", same, tt.wantSame)
			}
		})
	}
}

func TestStripSignature_ReplacesOnlySignatureFields(t *testing.T) {
	der := selfSignedECDSACertificate(t)
	unsigned, err := stripSignature(der)
	if err != nil {
		t.Fatalf("stripSignature() error = %v", err)
	}

	var before, after certificateDER
	if _, err := asn1.Unmarshal(der, &before); err != nil {
		t.Fatalf("decoding signed certificate: %v", err)
	}
	if _, err := asn1.Unmarshal(unsigned, &after); err != nil {
		t.Fatalf("decoding unsigned certificate: %v", err)
	}
	if !bytes.Equal(after.Algorithm.FullBytes, unsignedAlgorithmDER) {
		t.Errorf("signatureAlgorithm = % x, want % x", after.Algorithm.FullBytes, unsignedAlgorithmDER)
	}
	if !bytes.Equal(after.Signature.FullBytes, emptySignatureDER) {
		t.Errorf("signatureValue = % x, want % x", after.Signature.FullBytes, emptySignatureDER)
	}

	beforeFields := decodeFields(t, before.TBS.Bytes)
	afterFields := decodeFields(t, after.TBS.Bytes)
	if len(afterFields) != len(beforeFields) {
		t.Fatalf("TBSCertificate has %d fields, want %d", len(afterFields), len(beforeFields))
	}
	for i := range beforeFields {
		want := beforeFields[i].FullBytes
		if i == 2 {
			want = unsignedAlgorithmDER
		}
		if !bytes.Equal(afterFields[i].FullBytes, want) {
			t.Errorf("TBSCertificate field %d = % x, want % x", i, afterFields[i].FullBytes, want)
		}
	}
}

func TestStripSignature_RejectsMalformedCertificates(t *testing.T) {
	der := selfSignedECDSACertificate(t)
	var decoded certificateDER
	if _, err := asn1.Unmarshal(der, &decoded); err != nil {
		t.Fatalf("decoding certificate: %v", err)
	}
	tbsFields := decodeFields(t, decoded.TBS.Bytes)
	var withoutVersion [][]byte
	for _, field := range tbsFields[1:] {
		withoutVersion = append(withoutVersion, field.FullBytes)
	}

	tests := []struct {
		name string
		der  []byte
	}{
		{"not DER", []byte{0x01}},
		{"trailing data", append(slices.Clone(der), 0x00)},
		{"missing signatureValue", sequence(t, decoded.TBS.FullBytes, decoded.Algorithm.FullBytes)},
		{"TBSCertificate without version", sequence(t, sequence(t, withoutVersion...), decoded.Algorithm.FullBytes, decoded.Signature.FullBytes)},
		{"inner and outer signature algorithms differ", sequence(t, decoded.TBS.FullBytes, unsignedAlgorithmDER, decoded.Signature.FullBytes)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := stripSignature(tt.der); err == nil {
				t.Errorf("stripSignature() = % x, want error", got)
			}
		})
	}
}
