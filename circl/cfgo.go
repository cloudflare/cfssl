// +build cfgo

package circl

import (
	"crypto/x509"
	"encoding/asn1"

	circlPki "circl/pki"
	circlSign "circl/sign"
	circlSignSchemes "circl/sign/schemes"
)

type SignatureOpts = circlSign.SignatureOpts
type PublicKey = circlSign.PublicKey
type PrivateKey = circlSign.PrivateKey
type Scheme = circlSign.Scheme
type CertificateScheme = circlPki.CertificateScheme
type TLSScheme = circlPki.TLSScheme

func SchemeByName(name string) Scheme {
	return circlSignSchemes.ByName(name)
}

func AllSchemes() []Scheme {
	ret := []Scheme{}
	schemes := circlSignSchemes.All()

	for _, scheme := range schemes {
		// Only return those schemes that the Go fork supports
		if x509.SignatureAlgorithmByCirclScheme(scheme) == x509.UnknownSignatureAlgorithm {
			continue
		}
		ret = append(ret, scheme)
	}

	return ret
}

func SchemeByOid(oid asn1.ObjectIdentifier) Scheme {
	return circlPki.SchemeByOid(oid)
}

func SchemeByTLSIdentifier(id uint) Scheme {
	return circlPki.SchemeByTLSID(id)
}

func SchemeByX509PublicKeyAlgorithm(id x509.PublicKeyAlgorithm) Scheme {
	return x509.CirclSchemeByPublicKeyAlgorithm(id)
}

func UnmarshalPEMPublicKey(data []byte) (PublicKey, error) {
	return circlPki.UnmarshalPEMPublicKey(data)
}

func MarshalPEMPublicKey(pk PublicKey) ([]byte, error) {
	return circlPki.MarshalPEMPublicKey(pk)
}

func UnmarshalPKIXPublicKey(data []byte) (PublicKey, error) {
	return circlPki.UnmarshalPKIXPublicKey(data)
}

func MarshalPKIXPublicKey(pk PublicKey) ([]byte, error) {
	return circlPki.MarshalPKIXPublicKey(pk)
}

func UnmarshalPEMPrivateKey(data []byte) (PrivateKey, error) {
	return circlPki.UnmarshalPEMPrivateKey(data)
}

func MarshalPEMPrivateKey(sk PrivateKey) ([]byte, error) {
	return circlPki.MarshalPEMPrivateKey(sk)
}

func UnmarshalPKIXPrivateKey(data []byte) (PrivateKey, error) {
	return circlPki.UnmarshalPKIXPrivateKey(data)
}

func X509SignatureAlgorithmByScheme(scheme Scheme) x509.SignatureAlgorithm {
	return x509.SignatureAlgorithmByCirclScheme(scheme)
}
