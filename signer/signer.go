// Package signer implements certificate signature functionality for CF-SSL.
package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"net"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	cferr "github.com/cloudflare/cfssl/errors"
)

// Subject contains the information that should be used to override the
// subject information when signing a certificate.
type Subject struct {
	CN    string
	Names []csr.Name `json:"names"`
	Hosts []string   `json:"hosts"`
}

// SignRequest stores a signature request, which contains the hostname,
// the CSR, optional subject information, and the signature profile.
type SignRequest struct {
	Hostname string   `json:"hostname"`
	Request  string   `json:"certificate_request"`
	Subject  *Subject `json:"subject,omitempty"`
	Profile  string   `json:"profile"`
	Label    string   `json:"label"`
}

// Root is used to define where the Signer gets its public certificate
// and private keys for signing.
type Root struct {
	CertFile    string
	KeyFile     string
	ForceRemote bool
}

// appendIf appends to a if s is not an empty string.
func appendIf(s string, a *[]string) {
	if s != "" {
		*a = append(*a, s)
	}
}

// Name returns the PKIX name for the subject.
func (s *Subject) Name() pkix.Name {
	var name pkix.Name
	name.CommonName = s.CN

	for _, n := range s.Names {
		appendIf(n.C, &name.Country)
		appendIf(n.ST, &name.Province)
		appendIf(n.L, &name.Locality)
		appendIf(n.O, &name.Organization)
		appendIf(n.OU, &name.OrganizationalUnit)
	}
	return name
}

// A Signer contains a CA's certificate and private key for signing
// certificates, a Signing policy to refer to and a SignatureAlgorithm.
type Signer interface {
	Certificate() *x509.Certificate
	Policy() *config.Signing
	SetPolicy(*config.Signing)
	SigAlgo() x509.SignatureAlgorithm
	Sign(req SignRequest) (cert []byte, err error)
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
// builds a certificate template from it. If not nil, the subject
// information from subject will be used in place of the information in
// the CSR.
func ParseCertificateRequest(s Signer, csrBytes []byte, req *Subject) (template *x509.Certificate, err error) {
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		err = cferr.Wrap(cferr.CertificateError, cferr.ParseFailed, err)
		return
	}

	err = CheckSignature(csr, csr.SignatureAlgorithm, csr.RawTBSCertificateRequest, csr.Signature)
	if err != nil {
		err = cferr.Wrap(cferr.CertificateError, cferr.KeyMismatch, err)
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

// NewSigner generates a new certificate signer from a Root structure
// If the root structure specifies a force remote, then a remote signer
// is created, otherwise either a remote or local signer is generated
// based on the policy. For a local signer, the CertFile and KeyFile
// need to be defined.
func NewSigner(root Root, policy *config.Signing) (s Signer, err error) {
	if policy == nil {
		policy = &config.Signing{
			Profiles: map[string]*config.SigningProfile{},
			Default:  config.DefaultConfig(),
		}
	}

	if !policy.Valid() {
		return nil, cferr.New(cferr.PolicyError, cferr.InvalidPolicy)
	}

	if root.ForceRemote {
		s, err = NewRemoteSigner(policy)
	} else {
		if policy.NeedsLocalSigner() && policy.NeedsRemoteSigner() {
			// Currently we don't support a hybrid signer
			return nil, cferr.New(cferr.PolicyError, cferr.InvalidPolicy)
		}

		if policy.NeedsLocalSigner() {
			s, err = NewLocalSignerFromFile(root.CertFile, root.KeyFile, policy)
		}

		if policy.NeedsRemoteSigner() {
			s, err = NewRemoteSigner(policy)
		}
	}

	return
}
