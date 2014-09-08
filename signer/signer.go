// Package signer implements certificate signature functionality for CF-SSL.
package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"net"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	cferr "github.com/cloudflare/cfssl/errors"
)

// A Signer contains a CA's certificate and private key for signing
// certificates, a Signing policy to refer to and a SignatureAlgorithm.
type Signer interface {
	Certificate() *x509.Certificate
	Policy() *config.Signing
	SetPolicy(*config.Signing)
	SigAlgo() x509.SignatureAlgorithm
	Sign(string, []byte, *csr.CertificateRequest, string) (cert []byte, err error)
}

// DefaultSigAlgo returns an appropriate X.509 signature algorithm given
// the CA's private key.
func DefaultSigAlgo(priv interface{}) x509.SignatureAlgorithm {
	switch priv := priv.(type) {
	case *rsa.PrivateKey:
		keySize := priv.N.BitLen()
		switch {
		case keySize >= 4096:
			return x509.SHA512WithRSA
		case keySize >= 3072:
			return x509.SHA384WithRSA
		case keySize >= 2048:
			return x509.SHA256WithRSA
		default:
			return x509.SHA1WithRSA
		}
	case *ecdsa.PrivateKey:
		switch priv.Curve {
		case elliptic.P256():
			return x509.ECDSAWithSHA256
		case elliptic.P384():
			return x509.ECDSAWithSHA384
		case elliptic.P521():
			return x509.ECDSAWithSHA512
		default:
			return x509.ECDSAWithSHA1
		}
	default:
		return x509.UnknownSignatureAlgorithm
	}
}

// ParseCertificateRequest takes an incoming certificate request and
// builds a certificate template from it.
func ParseCertificateRequest(s Signer, csrBytes []byte, req *csr.CertificateRequest) (template *x509.Certificate, err error) {
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		err = cferr.New(cferr.CertificateError, cferr.ParseFailed, err)
		return
	}

	err = CheckSignature(csr, csr.SignatureAlgorithm, csr.RawTBSCertificateRequest, csr.Signature)
	if err != nil {
		err = cferr.New(cferr.CertificateError, cferr.KeyMismatch, err)
		return
	}

	template = &x509.Certificate{
		Subject:            csr.Subject,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,
		SignatureAlgorithm: s.SigAlgo(),
	}

	if req != nil {
		template.Subject = req.Name()
		for i := range req.Hosts {
			if ip := net.ParseIP(req.Hosts[i]); ip != nil {
				template.IPAddresses = append(template.IPAddresses, ip)
			} else {
				template.DNSNames = append(template.DNSNames, req.Hosts[i])
			}
		}
	}

	return
}

// CheckSignature verifies a signature made by the key on a CSR, such
// as on the CSR itself.
func CheckSignature(csr *x509.CertificateRequest, algo x509.SignatureAlgorithm, signed, signature []byte) error {
	var hashType crypto.Hash

	switch algo {
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1:
		hashType = crypto.SHA1
	case x509.SHA256WithRSA, x509.ECDSAWithSHA256:
		hashType = crypto.SHA256
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384:
		hashType = crypto.SHA384
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512:
		hashType = crypto.SHA512
	default:
		return x509.ErrUnsupportedAlgorithm
	}

	if !hashType.Available() {
		return x509.ErrUnsupportedAlgorithm
	}
	h := hashType.New()

	h.Write(signed)
	digest := h.Sum(nil)

	switch pub := csr.PublicKey.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(pub, hashType, digest, signature)
	case *ecdsa.PublicKey:
		ecdsaSig := new(struct{ R, S *big.Int })
		if _, err := asn1.Unmarshal(signature, ecdsaSig); err != nil {
			return err
		}
		if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
			return errors.New("x509: ECDSA signature contained zero or negative values")
		}
		if !ecdsa.Verify(pub, digest, ecdsaSig.R, ecdsaSig.S) {
			return errors.New("x509: ECDSA verification failure")
		}
		return nil
	}
	return x509.ErrUnsupportedAlgorithm
}
