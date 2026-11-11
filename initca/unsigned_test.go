package initca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

const leafName = "leaf.example.com"

func taiRawSubject(t *testing.T) []byte {
	t.Helper()
	name := pkix.RDNSequence{{{
		Type:  asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 25, 3},
		Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: 13, Bytes: []byte{0x82, 0xda, 0x4b, 0x31, 0x01, 0x01}},
	}}}
	der, err := asn1.Marshal(name)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestNewWithRawSubject(t *testing.T) {
	raw := taiRawSubject(t)
	certPEM, _, _, err := New(&csr.CertificateRequest{RawSubject: raw})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cert.RawSubject, raw) || !bytes.Equal(cert.RawIssuer, raw) {
		t.Errorf("subject/issuer differ from raw subject")
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Errorf("self-signature: %v", err)
	}
}

func TestNewUnsigned(t *testing.T) {
	raw := taiRawSubject(t)
	for _, kr := range []csr.KeyRequest{{A: "ecdsa", S: 256}, {A: "rsa", S: 2048}, {A: "ed25519"}, {A: "mldsa44"}} {
		t.Run(kr.A, func(t *testing.T) {
			kr := kr
			certPEM, keyPEM, err := NewUnsigned(&csr.CertificateRequest{RawSubject: raw, KeyRequest: &kr})
			if err != nil {
				t.Fatalf("NewUnsigned() error = %v", err)
			}
			priv, err := helpers.ParsePrivateKeyPEM(keyPEM)
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(certPEM)
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			wantAlg := []byte{0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x24}
			if !bytes.Equal(cert.RawSignatureAlgorithm, wantAlg) {
				t.Errorf("signatureAlgorithm = % x, want % x", cert.RawSignatureAlgorithm, wantAlg)
			}
			if len(cert.Signature) != 0 {
				t.Errorf("signature has %d bytes", len(cert.Signature))
			}
			if !bytes.Equal(cert.RawSubject, raw) || !bytes.Equal(cert.RawIssuer, raw) {
				t.Error("subject/issuer differ from raw subject")
			}
			if !cert.IsCA {
				t.Error("not a CA")
			}
			if !priv.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(cert.PublicKey) {
				t.Error("key mismatch")
			}
		})
	}
}

func TestNewUnsignedRequiresRawSubject(t *testing.T) {
	if _, _, err := NewUnsigned(&csr.CertificateRequest{CN: "x"}); err == nil {
		t.Error("want error")
	}
}

func TestUnsignRejectsTrailingPEM(t *testing.T) {
	certPEM, _, _, err := New(&csr.CertificateRequest{CN: "root"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Unsign(certPEM); err != nil {
		t.Fatalf("Unsign() error = %v", err)
	}
	if _, err := Unsign(append(certPEM, certPEM...)); err == nil {
		t.Error("want error for trailing PEM")
	}
}

func testCertificate(t *testing.T, template, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) (*x509.Certificate, []byte) {
	t.Helper()
	if parent == nil {
		parent = template
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, signer)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() error = %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, der
}

var (
	unsignedAlgorithmDER = []byte{0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x24}
	emptySignatureDER    = []byte{0x03, 0x01, 0x00}
)

// checkUnsignedEncoding checks RFC 9925, Section 3.1 against the DER: both
// signature fields are id-alg-unsigned with absent parameters and the
// signatureValue is a BIT STRING of length zero.
func checkUnsignedEncoding(t *testing.T, der []byte) {
	t.Helper()
	input := cryptobyte.String(der)
	var cert, tbs, outerAlg, signature cryptobyte.String
	if !input.ReadASN1(&cert, cbasn1.SEQUENCE) || !input.Empty() ||
		!cert.ReadASN1(&tbs, cbasn1.SEQUENCE) ||
		!cert.ReadASN1Element(&outerAlg, cbasn1.SEQUENCE) ||
		!cert.ReadASN1Element(&signature, cbasn1.BIT_STRING) || !cert.Empty() {
		t.Fatal("malformed certificate")
	}
	var version, serial, innerAlg cryptobyte.String
	if !tbs.ReadASN1Element(&version, cbasn1.Tag(0).Constructed().ContextSpecific()) ||
		!tbs.ReadASN1Element(&serial, cbasn1.INTEGER) ||
		!tbs.ReadASN1Element(&innerAlg, cbasn1.SEQUENCE) {
		t.Fatal("malformed TBSCertificate")
	}
	if !bytes.Equal(outerAlg, unsignedAlgorithmDER) {
		t.Errorf("signatureAlgorithm = % x, want % x", []byte(outerAlg), unsignedAlgorithmDER)
	}
	if !bytes.Equal(innerAlg, unsignedAlgorithmDER) {
		t.Errorf("TBSCertificate.signature = % x, want % x", []byte(innerAlg), unsignedAlgorithmDER)
	}
	if !bytes.Equal(signature, emptySignatureDER) {
		t.Errorf("signatureValue = % x, want % x", []byte(signature), emptySignatureDER)
	}
}

func parseUnsigned(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	out, err := Unsign(certPEM)
	if err != nil {
		t.Fatalf("Unsign() error = %v", err)
	}
	block, _ := pem.Decode(out)
	checkUnsignedEncoding(t, block.Bytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("x509.ParseCertificate() error = %v", err)
	}
	return cert
}

func TestUnsignKeepsNonRootCertificates(t *testing.T) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	root, _ := testCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, nil, &rootKey.PublicKey, rootKey)
	intermediate, intermediateDER := testCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "intermediate"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, root, &intKey.PublicKey, rootKey)
	leaf, leafDER := testCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "leaf"}, DNSNames: []string{leafName},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, intermediate, &leafKey.PublicKey, intKey)

	for _, tt := range []struct {
		name string
		orig *x509.Certificate
		der  []byte
	}{
		{"intermediate", intermediate, intermediateDER},
		{"end entity", leaf, leafDER},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := parseUnsigned(t, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tt.der}))
			if !bytes.Equal(got.RawIssuer, tt.orig.RawIssuer) || !bytes.Equal(got.RawSubject, tt.orig.RawSubject) {
				t.Error("issuer or subject changed")
			}
			if !bytes.Equal(got.RawSubjectPublicKeyInfo, tt.orig.RawSubjectPublicKeyInfo) {
				t.Error("public key changed")
			}
			if len(tt.orig.AuthorityKeyId) == 0 {
				t.Fatal("test certificate has no authority key identifier")
			}
			if len(got.AuthorityKeyId) != 0 {
				t.Errorf("AuthorityKeyId = % x, want it removed (RFC 9925, Section 3.3)", got.AuthorityKeyId)
			}
			if !bytes.Equal(got.SubjectKeyId, tt.orig.SubjectKeyId) {
				t.Errorf("SubjectKeyId = % x, want original % x", got.SubjectKeyId, tt.orig.SubjectKeyId)
			}
			if got.SerialNumber.Cmp(tt.orig.SerialNumber) != 0 || !got.NotBefore.Equal(tt.orig.NotBefore) || !got.NotAfter.Equal(tt.orig.NotAfter) {
				t.Error("serial number or validity changed")
			}
			if got.IsCA != tt.orig.IsCA || got.KeyUsage != tt.orig.KeyUsage {
				t.Error("basic constraints or key usage changed")
			}
			if !slices.Equal(got.DNSNames, tt.orig.DNSNames) {
				t.Errorf("DNSNames = %v, want %v", got.DNSNames, tt.orig.DNSNames)
			}
		})
	}

	// An unsigned intermediate placed directly in the trust store anchors
	// chains for the certificates it issued.
	unsignedIntermediate := parseUnsigned(t, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediateDER}))
	roots := x509.NewCertPool()
	roots.AddCert(unsignedIntermediate)
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: leafName})
	if err != nil {
		t.Fatalf("leaf.Verify() error = %v", err)
	}
	if anchor := chains[0][len(chains[0])-1]; !anchor.Equal(unsignedIntermediate) {
		t.Errorf("chain ends at %v, want the unsigned intermediate", anchor.Subject)
	}
}

// withUniqueID returns the DER certificate in certPEM with a unique ID field
// of the given context-specific tag (1 for issuerUniqueID, 2 for
// subjectUniqueID) inserted after the subjectPublicKeyInfo.
func withUniqueID(t *testing.T, certPEM []byte, tag int, id []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	input := cryptobyte.String(block.Bytes)
	var cert, tbs, sigAlg, sigValue cryptobyte.String
	if !input.ReadASN1(&cert, cbasn1.SEQUENCE) || !cert.ReadASN1(&tbs, cbasn1.SEQUENCE) ||
		!cert.ReadASN1Element(&sigAlg, cbasn1.SEQUENCE) || !cert.ReadASN1Element(&sigValue, cbasn1.BIT_STRING) {
		t.Fatal("malformed certificate")
	}
	var version, serial, tbsSigAlg, issuer, validity, subject, spki cryptobyte.String
	if !tbs.ReadASN1Element(&version, cbasn1.Tag(0).Constructed().ContextSpecific()) ||
		!tbs.ReadASN1Element(&serial, cbasn1.INTEGER) || !tbs.ReadASN1Element(&tbsSigAlg, cbasn1.SEQUENCE) ||
		!tbs.ReadASN1Element(&issuer, cbasn1.SEQUENCE) || !tbs.ReadASN1Element(&validity, cbasn1.SEQUENCE) ||
		!tbs.ReadASN1Element(&subject, cbasn1.SEQUENCE) || !tbs.ReadASN1Element(&spki, cbasn1.SEQUENCE) {
		t.Fatal("malformed TBSCertificate")
	}

	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(c *cryptobyte.Builder) {
		c.AddASN1(cbasn1.SEQUENCE, func(t *cryptobyte.Builder) {
			for _, field := range [][]byte{version, serial, tbsSigAlg, issuer, validity, subject, spki} {
				t.AddBytes(field)
			}
			t.AddASN1(cbasn1.Tag(tag).ContextSpecific(), func(u *cryptobyte.Builder) {
				u.AddBytes(id)
			})
			t.AddBytes(tbs)
		})
		c.AddBytes(sigAlg)
		c.AddBytes(sigValue)
	})
	der, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestUnsignRejectsIssuerUniqueID(t *testing.T) {
	certPEM, _, _, err := New(&csr.CertificateRequest{CN: "root"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Unsign(withUniqueID(t, certPEM, 1, []byte{0x00, 0x01})); err == nil {
		t.Error("Unsign() accepted a certificate with an issuerUniqueID")
	}
}

func TestUnsignKeepsSubjectUniqueID(t *testing.T) {
	certPEM, _, _, err := New(&csr.CertificateRequest{CN: "root"})
	if err != nil {
		t.Fatal(err)
	}
	id := []byte{0x00, 0xa5}
	got := parseUnsigned(t, withUniqueID(t, certPEM, 2, id))
	if !bytes.Contains(got.Raw, append([]byte{0x82, byte(len(id))}, id...)) {
		t.Error("subjectUniqueID was not kept")
	}
	if len(got.Extensions) == 0 {
		t.Error("extensions after the subjectUniqueID were dropped")
	}
}

func TestUnsignHandlesEmptyNames(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	parentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	parent, _ := testCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, nil, &parentKey.PublicKey, parentKey)

	t.Run("empty subject with a SAN is kept", func(t *testing.T) {
		_, der := testCertificate(t, &x509.Certificate{
			SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			DNSNames: []string{leafName},
		}, parent, &key.PublicKey, parentKey)
		got := parseUnsigned(t, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		if !bytes.Equal(got.RawSubject, []byte{0x30, 0x00}) {
			t.Errorf("RawSubject = % x, want an empty Name", got.RawSubject)
		}
		if !slices.Equal(got.DNSNames, []string{leafName}) {
			t.Errorf("DNSNames = %v, want [%s]", got.DNSNames, leafName)
		}
		for _, ext := range got.Extensions {
			if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) && !ext.Critical {
				t.Error("subjectAltName of an empty subject is not critical")
			}
		}
	})

	t.Run("empty issuer is rejected", func(t *testing.T) {
		_, der := testCertificate(t, &x509.Certificate{
			SerialNumber: big.NewInt(3), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			DNSNames: []string{leafName},
		}, nil, &key.PublicKey, key)
		if _, err := Unsign(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err == nil {
			t.Error("Unsign() accepted a certificate with an empty issuer")
		}
	})
}

func TestUnsignRemovesIssuerExtensions(t *testing.T) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	root, _ := testCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, nil, &rootKey.PublicKey, rootKey)

	issuerAltName := asn1.ObjectIdentifier{2, 5, 29, 18}
	custom := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}
	template := func(extra ...pkix.Extension) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "leaf"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			ExtraExtensions: extra,
		}
	}
	hasExtension := func(cert *x509.Certificate, id asn1.ObjectIdentifier) *pkix.Extension {
		for i := range cert.Extensions {
			if cert.Extensions[i].Id.Equal(id) {
				return &cert.Extensions[i]
			}
		}
		return nil
	}

	t.Run("other extensions are kept in order", func(t *testing.T) {
		orig, der := testCertificate(t, template(
			pkix.Extension{Id: issuerAltName, Value: []byte{0x30, 0x03, 0x82, 0x01, 'x'}},
			pkix.Extension{Id: custom, Critical: false, Value: []byte{0x05, 0x00}},
		), root, &leafKey.PublicKey, rootKey)
		got := parseUnsigned(t, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		if hasExtension(orig, issuerAltName) == nil || len(orig.AuthorityKeyId) == 0 {
			t.Fatal("test certificate lacks the issuer extensions")
		}
		if hasExtension(got, issuerAltName) != nil {
			t.Error("issuerAltName was kept")
		}
		if len(got.AuthorityKeyId) != 0 {
			t.Error("authorityKeyIdentifier was kept")
		}
		kept := hasExtension(got, custom)
		if kept == nil || !bytes.Equal(kept.Value, []byte{0x05, 0x00}) {
			t.Errorf("custom extension = %v, want it kept unchanged", kept)
		}
		if len(got.Extensions) != len(orig.Extensions)-2 {
			t.Errorf("%d extensions, want %d", len(got.Extensions), len(orig.Extensions)-2)
		}
	})

	t.Run("no extensions field is left empty", func(t *testing.T) {
		orig, der := testCertificate(t, template(), root, &leafKey.PublicKey, rootKey)
		if len(orig.Extensions) != 1 || len(orig.AuthorityKeyId) == 0 {
			t.Fatalf("test certificate has %d extensions, want only the authority key identifier", len(orig.Extensions))
		}
		got := parseUnsigned(t, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		if len(got.Extensions) != 0 {
			t.Errorf("%d extensions, want none", len(got.Extensions))
		}
		tbs := cryptobyte.String(got.RawTBSCertificate)
		var content cryptobyte.String
		if !tbs.ReadASN1(&content, cbasn1.SEQUENCE) {
			t.Fatal("malformed TBSCertificate")
		}
		for !content.Empty() {
			var tag cbasn1.Tag
			var element cryptobyte.String
			if !content.ReadAnyASN1Element(&element, &tag) {
				t.Fatal("malformed TBSCertificate field")
			}
			if tag == cbasn1.Tag(3).Constructed().ContextSpecific() {
				t.Error("TBSCertificate has an extensions field")
			}
		}
	})
}

// An unsigned certificate must not stand in for a signature in a path
// (RFC 9925, Section 4).
func TestUnsignedIntermediateIsNotAcceptedInPath(t *testing.T) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	root, _ := testCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, nil, &rootKey.PublicKey, rootKey)
	intermediate, intermediateDER := testCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "intermediate"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, root, &intKey.PublicKey, rootKey)
	leaf, _ := testCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "leaf"}, DNSNames: []string{leafName},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, intermediate, &leafKey.PublicKey, intKey)

	unsigned := parseUnsigned(t, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediateDER}))
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	intermediates.AddCert(unsigned)
	if chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: leafName}); err == nil {
		t.Errorf("leaf.Verify() accepted a path through an unsigned intermediate: %d chains", len(chains))
	}
	if err := unsigned.CheckSignatureFrom(root); err == nil {
		t.Error("CheckSignatureFrom() accepted an unsigned certificate")
	}
}

func TestNewUnsignedHasNoSANs(t *testing.T) {
	certPEM, _, err := NewUnsigned(&csr.CertificateRequest{
		RawSubject: taiRawSubject(t),
		Hosts:      []string{"192.0.2.1", "a.example.com", "x@example.com", "https://example.com/ca"},
	})
	if err != nil {
		t.Fatalf("NewUnsigned() error = %v", err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.DNSNames) != 0 || len(cert.IPAddresses) != 0 || len(cert.EmailAddresses) != 0 || len(cert.URIs) != 0 {
		t.Errorf("certificate has SANs %v %v %v %v, want none", cert.DNSNames, cert.IPAddresses, cert.EmailAddresses, cert.URIs)
	}
}

func TestNewUnsignedDoesNotMutateRequest(t *testing.T) {
	req := &csr.CertificateRequest{RawSubject: taiRawSubject(t), Hosts: []string{"a.example.com"}}
	if _, _, err := NewUnsigned(req); err != nil {
		t.Fatalf("NewUnsigned() error = %v", err)
	}
	if len(req.Hosts) != 1 {
		t.Errorf("Hosts = %v, want unchanged", req.Hosts)
	}
}

func TestNewRejectsEmptyRawSubject(t *testing.T) {
	empty := []byte{0x30, 0x00}
	if _, _, _, err := New(&csr.CertificateRequest{RawSubject: empty}); err == nil {
		t.Error("New() accepted an empty raw subject")
	}
	if _, _, err := NewUnsigned(&csr.CertificateRequest{RawSubject: empty}); err == nil {
		t.Error("NewUnsigned() accepted an empty raw subject")
	}
}

func TestRenewPreservesRawSubject(t *testing.T) {
	raw := taiRawSubject(t)
	for _, alg := range []csr.KeyRequest{{A: "ecdsa", S: 256}, {A: "ed25519"}, {A: "mldsa44"}} {
		t.Run(alg.A, func(t *testing.T) {
			alg := alg
			signedPEM, _, key, err := New(&csr.CertificateRequest{RawSubject: raw, KeyRequest: &alg})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			ca, err := helpers.ParseCertificatePEM(signedPEM)
			if err != nil {
				t.Fatal(err)
			}
			priv, err := helpers.ParsePrivateKeyPEM(key)
			if err != nil {
				t.Fatal(err)
			}
			renewedPEM, err := RenewFromSigner(ca, priv)
			if err != nil {
				t.Fatalf("RenewFromSigner() error = %v", err)
			}
			renewed, err := helpers.ParseCertificatePEM(renewedPEM)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(renewed.RawSubject, raw) || !bytes.Equal(renewed.RawIssuer, raw) {
				t.Errorf("renewed subject = % x, want % x", renewed.RawSubject, raw)
			}
		})
	}
}

func TestRenewRejectsUnsigned(t *testing.T) {
	certPEM, keyPEM, err := NewUnsigned(&csr.CertificateRequest{RawSubject: taiRawSubject(t)})
	if err != nil {
		t.Fatalf("NewUnsigned() error = %v", err)
	}
	cert, err := helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := helpers.ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := RenewFromSigner(cert, priv); err == nil {
		t.Errorf("RenewFromSigner() = %d bytes, want error", len(out))
	}
}

// otherKeySigner reports the public key of decoy but signs with its embedded
// key, so the signature does not verify under the reported key.
type otherKeySigner struct {
	crypto.Signer
	decoy crypto.PublicKey
}

func (s otherKeySigner) Public() crypto.PublicKey {
	return s.decoy
}

// swappingSigner reports the public key of decoy until it signs, and the
// public key of its embedded signer afterwards.
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

func TestNewUnsignedFromSigner(t *testing.T) {
	raw := taiRawSubject(t)
	priv, err := (&csr.KeyRequest{A: "ecdsa", S: 256}).Generate()
	if err != nil {
		t.Fatal(err)
	}
	signer := priv.(crypto.Signer)

	certPEM, err := NewUnsignedFromSigner(&csr.CertificateRequest{RawSubject: raw, Hosts: []string{"a.example.com"}}, signer)
	if err != nil {
		t.Fatalf("NewUnsignedFromSigner() error = %v", err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cert.RawSubject, raw) || !bytes.Equal(cert.RawIssuer, raw) {
		t.Error("subject/issuer differ from raw subject")
	}
	if len(cert.DNSNames) != 0 {
		t.Errorf("DNSNames = %v, want none", cert.DNSNames)
	}
	if !cert.PublicKey.(*ecdsa.PublicKey).Equal(signer.Public()) {
		t.Error("public key differs from signer")
	}
	if len(cert.Signature) != 0 {
		t.Errorf("signature has %d bytes, want 0", len(cert.Signature))
	}
}

func TestNewUnsignedFromSignerRejectsMismatchedKey(t *testing.T) {
	priv, err := (&csr.KeyRequest{A: "ecdsa", S: 256}).Generate()
	if err != nil {
		t.Fatal(err)
	}
	other, err := (&csr.KeyRequest{A: "ecdsa", S: 256}).Generate()
	if err != nil {
		t.Fatal(err)
	}
	signer := otherKeySigner{Signer: priv.(crypto.Signer), decoy: other.(crypto.Signer).Public()}

	certPEM, err := NewUnsignedFromSigner(&csr.CertificateRequest{RawSubject: taiRawSubject(t)}, signer)
	if err == nil {
		t.Fatalf("NewUnsignedFromSigner() = %d bytes, want error", len(certPEM))
	}
}

func TestNewUnsignedFromSignerRejectsSwappingKey(t *testing.T) {
	priv, err := (&csr.KeyRequest{A: "ecdsa", S: 256}).Generate()
	if err != nil {
		t.Fatal(err)
	}
	other, err := (&csr.KeyRequest{A: "ecdsa", S: 256}).Generate()
	if err != nil {
		t.Fatal(err)
	}
	signer := &swappingSigner{Signer: priv.(crypto.Signer), decoy: other.(crypto.Signer).Public()}

	certPEM, err := NewUnsignedFromSigner(&csr.CertificateRequest{RawSubject: taiRawSubject(t)}, signer)
	if err == nil {
		t.Fatalf("NewUnsignedFromSigner() = %d bytes, want error", len(certPEM))
	}
}

func TestNewUnsignedFromSignerRejectsNilSigner(t *testing.T) {
	if _, err := NewUnsignedFromSigner(&csr.CertificateRequest{RawSubject: taiRawSubject(t)}, nil); err == nil {
		t.Error("NewUnsignedFromSigner(nil) succeeded, want error")
	}
}

// Signature verification must reject id-alg-unsigned (RFC 9925, Section 4).
func TestUnsignedRootFailsSignatureChecks(t *testing.T) {
	certPEM, _, err := NewUnsigned(&csr.CertificateRequest{RawSubject: taiRawSubject(t)})
	if err != nil {
		t.Fatalf("NewUnsigned() error = %v", err)
	}
	if _, err := helpers.ParseSelfSignedCertificatePEM(certPEM); err == nil {
		t.Error("ParseSelfSignedCertificatePEM() accepted an unsigned certificate")
	}
	cert, err := helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.CheckSignatureFrom(cert); err == nil {
		t.Error("CheckSignatureFrom() accepted an unsigned certificate")
	}
}
