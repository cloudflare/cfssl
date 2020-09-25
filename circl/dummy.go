// +build !cfgo

package circl

import (
	"crypto"
	"crypto/x509"
	"encoding"
	"encoding/asn1"
	"errors"
)

// When we're not using http://github.com/cloudflare/go, we can't use any
// of the signature schemes from Circl, so we'll just put a dummy API here.

// SignatureOpts contain the options for Scheme.Sign
type SignatureOpts struct {
	Context string
}

// PublicKey represents the public key of a signature keypair
type PublicKey interface {
	Scheme() Scheme
	encoding.BinaryMarshaler
	Equal(crypto.PublicKey) bool
}

// PrivateKey represents the private key of a signature keypair
type PrivateKey interface {
	Scheme() Scheme
	crypto.Signer
	encoding.BinaryMarshaler
	Equal(crypto.PrivateKey) bool
}

// Scheme represents a specific instance of a signature scheme.
type Scheme interface {
	GenerateKey() (PublicKey, PrivateKey, error)
	Sign(sk PrivateKey, message []byte, opts *SignatureOpts) []byte
	Verify(pk PublicKey, message []byte, signature []byte, opts *SignatureOpts) bool
	DeriveKey(seed []byte) (PublicKey, PrivateKey)
	UnmarshalBinaryPublicKey([]byte) (PublicKey, error)
	UnmarshalBinaryPrivateKey([]byte) (PrivateKey, error)
	PublicKeySize() uint
	PrivateKeySize() uint
	Name() string
	SignatureSize() uint
	SeedSize() uint
}

// CertificateScheme represents a scheme instance that can be used in
// x509 certificates
type CertificateScheme interface {
	Oid() asn1.ObjectIdentifier
}

// TLSScheme represents a scheme instance that can be used in TLS
type TLSScheme interface {
	TLSIdentifier() uint
}

// SchemeByName returns a scheme by name
func SchemeByName(name string) Scheme {
	return nil
}

// AllSchemes returns a list of all schemes
func AllSchemes() []Scheme {
	return []Scheme{}
}

// SchemeByOid returns a scheme by x509 oid
func SchemeByOid(oid asn1.ObjectIdentifier) Scheme {
	return nil
}

// SchemeByTLSIdentifier returns a scheme by TLS algorithm identifier
func SchemeByTLSIdentifier(id uint) Scheme {
	return nil
}

// UnmarshalPEMPublicKey unmarshals a public key in PEM format
func UnmarshalPEMPublicKey(data []byte) (PublicKey, error) {
	return nil, errors.New("not supported")
}

// MarshalPEMPublicKey marhshals a public key to PEM format
func MarshalPEMPublicKey(pk PublicKey) ([]byte, error) {
	return nil, errors.New("not supported")
}

// UnmarshalPKIXPublicKey unmarshals a public key in PKIX format
func UnmarshalPKIXPublicKey(data []byte) (PublicKey, error) {
	return nil, errors.New("not supported")
}

// MarshalPKIXPublicKey marhshals a public key in PKIX format
func MarshalPKIXPublicKey(pk PublicKey) ([]byte, error) {
	return nil, errors.New("not supported")
}

// UnmarshalPEMPrivateKey unmarshals a private key in PEM format
func UnmarshalPEMPrivateKey(data []byte) (PrivateKey, error) {
	return nil, errors.New("not supported")
}

// MarshalPEMPrivateKey marshals a private key in PEM format
func MarshalPEMPrivateKey(sk PrivateKey) ([]byte, error) {
	return nil, errors.New("not supported")
}

// UnmarshalPKIXPrivateKey unmarshals a private key in PKIX format
func UnmarshalPKIXPrivateKey(data []byte) (PrivateKey, error) {
	return nil, errors.New("not supported")
}

// SchemeByX509PublicKeyAlgorithm returns the scheme associated to the
// x509.PublicKeyAlgorithm used internally by Go
func SchemeByX509PublicKeyAlgorithm(id x509.PublicKeyAlgorithm) Scheme {
	return nil
}

// X509SignatureAlgorithmByScheme returns the x509.SignatureAlgorithm
// corresponding to the given scheme
func X509SignatureAlgorithmByScheme(scheme Scheme) x509.SignatureAlgorithm {
	return x509.UnknownSignatureAlgorithm
}
