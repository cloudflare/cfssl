// Package helpers implements utility functionality common to many
// CF-SSL packages.
package helpers

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"time"

	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/log"
)

// OneYear is a time.Duration representing a year's worth of seconds.
const OneYear = 8760 * time.Hour

// OneDay is a time.Duration representing a day's worth of seconds.
const OneDay = 24 * time.Hour

// KeyLength returns the bit size of ECDSA or RSA PublicKey
func KeyLength(key interface{}) int {
	if key == nil {
		return 0
	}
	if ecdsaKey, ok := key.(*ecdsa.PublicKey); ok {
		return ecdsaKey.Curve.Params().BitSize
	} else if rsaKey, ok := key.(*rsa.PublicKey); ok {
		return rsaKey.N.BitLen()
	}

	return 0
}

// ExpiryTime returns the time when the certificate chain is expired.
func ExpiryTime(chain []*x509.Certificate) *time.Time {
	if len(chain) == 0 {
		return nil
	}
	notAfter := chain[0].NotAfter
	for _, cert := range chain {
		if cert.NotAfter.Before(notAfter) {
			notAfter = cert.NotAfter
		}
	}
	return &notAfter
}

// SignatureString returns the TLS signature string corresponding to
// an X509 signature algorithm.
func SignatureString(alg x509.SignatureAlgorithm) string {
	switch alg {
	case x509.MD2WithRSA:
		return "MD2WithRSA"
	case x509.MD5WithRSA:
		return "MD5WithRSA"
	case x509.SHA1WithRSA:
		return "SHA1WithRSA"
	case x509.SHA256WithRSA:
		return "SHA256WithRSA"
	case x509.SHA384WithRSA:
		return "SHA384WithRSA"
	case x509.SHA512WithRSA:
		return "SHA512WithRSA"
	case x509.DSAWithSHA1:
		return "DSAWithSHA1"
	case x509.DSAWithSHA256:
		return "DSAWithSHA256"
	case x509.ECDSAWithSHA1:
		return "ECDSAWithSHA1"
	case x509.ECDSAWithSHA256:
		return "ECDSAWithSHA256"
	case x509.ECDSAWithSHA384:
		return "ECDSAWithSHA384"
	case x509.ECDSAWithSHA512:
		return "ECDSAWithSHA512"
	default:
		return "Unknown Signature"
	}
}

// HashAlgoString returns the hash algorithm name contains in the signature
// method.
func HashAlgoString(alg x509.SignatureAlgorithm) string {
	switch alg {
	case x509.MD2WithRSA:
		return "MD2"
	case x509.MD5WithRSA:
		return "MD5"
	case x509.SHA1WithRSA:
		return "SHA1"
	case x509.SHA256WithRSA:
		return "SHA256"
	case x509.SHA384WithRSA:
		return "SHA384"
	case x509.SHA512WithRSA:
		return "SHA512"
	case x509.DSAWithSHA1:
		return "SHA1"
	case x509.DSAWithSHA256:
		return "SHA256"
	case x509.ECDSAWithSHA1:
		return "SHA1"
	case x509.ECDSAWithSHA256:
		return "SHA256"
	case x509.ECDSAWithSHA384:
		return "SHA384"
	case x509.ECDSAWithSHA512:
		return "SHA512"
	default:
		return "Unknown Hash Algorithm"
	}
}

// ParseCertificatesPEM parses a sequence of PEM-encoded certificate and returns them.
func ParseCertificatesPEM(certsPEM []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	var err error
	certsPEM = bytes.TrimSpace(certsPEM)
	for len(certsPEM) > 0 {
		var cert *x509.Certificate
		cert, certsPEM, err = ParseOneCertificateFromPEM(certsPEM)
		if err != nil {
			return nil, cferr.New(cferr.CertificateError, cferr.ParseFailed)
		} else if cert == nil {
			break
		}

		certs = append(certs, cert)
	}
	if len(certsPEM) > 0 {
		return nil, cferr.New(cferr.CertificateError, cferr.DecodeFailed)
	}
	return certs, nil
}

// ParseSelfSignedCertificatePEM parses a PEM-encoded certificate and check if it is self-signed.
func ParseSelfSignedCertificatePEM(certPEM []byte) (*x509.Certificate, error) {
	cert, err := ParseCertificatePEM(certPEM)
	if err != nil {
		return nil, err
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		return nil, cferr.Wrap(cferr.CertificateError, cferr.VerifyFailed, err)
	}
	return cert, nil
}

// ParseCertificatePEM parses and returns a PEM-encoded certificate.
func ParseCertificatePEM(certPEM []byte) (*x509.Certificate, error) {
	certPEM = bytes.TrimSpace(certPEM)
	cert, rest, err := ParseOneCertificateFromPEM(certPEM)
	if err != nil {
		// Log the actual parsing error but throw a default parse error message.
		log.Debugf("Certificate parsing error: %v", err)
		return nil, cferr.New(cferr.CertificateError, cferr.ParseFailed)
	} else if cert == nil {
		return nil, cferr.New(cferr.CertificateError, cferr.DecodeFailed)
	} else if len(rest) > 0 {
		return nil, cferr.Wrap(cferr.CertificateError, cferr.ParseFailed, errors.New("The PEM file should contain only one certificate."))
	}
	return cert, nil
}

// ParseOneCertificateFromPEM attempts to parse one certificate from the top of the certsPEM,
// which may contain multiple certs.
func ParseOneCertificateFromPEM(certsPEM []byte) (cert *x509.Certificate, rest []byte, err error) {
	block, rest := pem.Decode(certsPEM)
	if block == nil {
		return nil, rest, nil
	}
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, rest, err
	}
	return
}

// ParsePrivateKeyPEM parses and returns a PEM-encoded private
// key. The private key may be either an unencrypted PKCS#8, PKCS#1,
// or elliptic private key.
func ParsePrivateKeyPEM(keyPEM []byte) (key crypto.Signer, err error) {
	keyDER, _ := pem.Decode(keyPEM)
	if keyDER == nil {
		return nil, cferr.New(cferr.PrivateKeyError, cferr.DecodeFailed)
	}
	if procType, ok := keyDER.Headers["Proc-Type"]; ok {
		if strings.Contains(procType, "ENCRYPTED") {
			return nil, cferr.New(cferr.PrivateKeyError, cferr.Encrypted)
		}
	}
	return ParsePrivateKeyDER(keyDER.Bytes)
}

// ParsePrivateKeyDER parses a PKCS #1, PKCS #8, or elliptic curve
// DER-encoded private key. The key must not be in PEM format.
func ParsePrivateKeyDER(keyDER []byte) (key crypto.Signer, err error) {
	generalKey, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		generalKey, err = x509.ParsePKCS1PrivateKey(keyDER)
		if err != nil {
			generalKey, err = x509.ParseECPrivateKey(keyDER)
			if err != nil {
				// We don't include the actual error into
				// the final error. The reason might be
				// we don't want to leak any info about
				// the private key.
				return nil, cferr.New(cferr.PrivateKeyError,
					cferr.ParseFailed)
			}
		}
	}

	switch generalKey.(type) {
	case *rsa.PrivateKey:
		return generalKey.(*rsa.PrivateKey), nil
	case *ecdsa.PrivateKey:
		return generalKey.(*ecdsa.PrivateKey), nil
	}

	return nil, cferr.New(cferr.PrivateKeyError, cferr.ParseFailed)
}
