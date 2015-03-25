// Package signer implements certificate signature functionality for CF-SSL.
package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math"
	"math/big"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	cferr "github.com/cloudflare/cfssl/errors"
)

// MaxPathLen is the default path length for a new CA certificate.
var MaxPathLen = 2

// Subject contains the information that should be used to override the
// subject information when signing a certificate.
type Subject struct {
	CN    string
	Names []csr.Name `json:"names"`
}

// SignRequest stores a signature request, which contains the hostname,
// the CSR, optional subject information, and the signature profile.
type SignRequest struct {
	Hosts   []string `json:"hosts"`
	Request string   `json:"certificate_request"`
	Subject *Subject `json:"subject,omitempty"`
	Profile string   `json:"profile"`
	Label   string   `json:"label"`
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

// SplitHosts takes a comma-spearated list of hosts and returns a slice
// with the hosts split
func SplitHosts(hostList string) []string {
	return strings.Split(hostList, ",")
}

// A Signer contains a CA's certificate and private key for signing
// certificates, a Signing policy to refer to and a SignatureAlgorithm.
type Signer interface {
	Certificate(label, profile string) (*x509.Certificate, error)
	Policy() *config.Signing
	SetPolicy(*config.Signing)
	SigAlgo() x509.SignatureAlgorithm
	Sign(req SignRequest) (cert []byte, err error)
}

// DefaultSigAlgo returns an appropriate X.509 signature algorithm given
// the CA's private key.
func DefaultSigAlgo(priv crypto.Signer) x509.SignatureAlgorithm {
	pub := priv.Public()
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		keySize := pub.N.BitLen()
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
	case *ecdsa.PublicKey:
		switch pub.Curve {
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
// the CSR. The same is true for the list of hosts.
func ParseCertificateRequest(s Signer, csrBytes []byte) (template *x509.Certificate, err error) {
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

type subjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

// ComputeSKI derives an SKI from the certificate's public key in a
// standard manner. This is done by computing the SHA-1 digest of the
// SubjectPublicKeyInfo component of the certificate.
func ComputeSKI(template *x509.Certificate) ([]byte, error) {
	pub := template.PublicKey
	encodedPub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	var subPKI subjectPublicKeyInfo
	_, err = asn1.Unmarshal(encodedPub, &subPKI)
	if err != nil {
		return nil, err
	}

	pubHash := sha1.Sum(subPKI.SubjectPublicKey.Bytes)
	return pubHash[:], nil
}

// FillTemplate is a utility function that tries to load as much of
// the certificate template as possible from the profiles and current
// template. It fills in the key uses, expiration, revocation URLs,
// serial number, and SKI.
func FillTemplate(template *x509.Certificate, defaultProfile, profile *config.SigningProfile) error {
	ski, err := ComputeSKI(template)

	var (
		eku             []x509.ExtKeyUsage
		ku              x509.KeyUsage
		backdate        time.Duration
		expiry          time.Duration
		notBefore       time.Time
		notAfter        time.Time
		crlURL, ocspURL string
	)

	// The third value returned from Usages is a list of unknown key usages.
	// This should be used when validating the profile at load, and isn't used
	// here.
	ku, eku, _ = profile.Usages()
	if profile.IssuerURL == nil {
		profile.IssuerURL = defaultProfile.IssuerURL
	}

	if ku == 0 && len(eku) == 0 {
		return cferr.New(cferr.PolicyError, cferr.NoKeyUsages)
	}

	if expiry = profile.Expiry; expiry == 0 {
		expiry = defaultProfile.Expiry
	}

	if crlURL = profile.CRL; crlURL == "" {
		crlURL = defaultProfile.CRL
	}
	if ocspURL = profile.OCSP; ocspURL == "" {
		ocspURL = defaultProfile.OCSP
	}
	if backdate = profile.Backdate; backdate == 0 {
		backdate = -5 * time.Minute
	} else {
		backdate = -1 * profile.Backdate
	}

	if !profile.NotBefore.IsZero() {
		notBefore = profile.NotBefore.UTC()
	} else {
		notBefore = time.Now().Round(time.Minute).Add(backdate).UTC()
	}

	if !profile.NotAfter.IsZero() {
		notAfter = profile.NotAfter.UTC()
	} else {
		notAfter = notBefore.Add(expiry).UTC()
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).SetInt64(math.MaxInt64))
	if err != nil {
		return cferr.Wrap(cferr.CertificateError, cferr.Unknown, err)
	}

	template.SerialNumber = serialNumber
	template.NotBefore = notBefore
	template.NotAfter = notAfter
	template.KeyUsage = ku
	template.ExtKeyUsage = eku
	template.BasicConstraintsValid = true
	template.IsCA = profile.CA
	template.SubjectKeyId = ski

	if ocspURL != "" {
		template.OCSPServer = []string{ocspURL}
	}
	if crlURL != "" {
		template.CRLDistributionPoints = []string{crlURL}
	}

	if len(profile.IssuerURL) != 0 {
		template.IssuingCertificateURL = profile.IssuerURL
	}
	if len(profile.Policies) != 0 {
		template.PolicyIdentifiers = profile.Policies
	}
	if profile.OCSPNoCheck {
		ocspNoCheckExtension := pkix.Extension{
			Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5},
			Critical: false,
			Value:    []byte{0x05, 0x00},
		}
		template.ExtraExtensions = append(template.ExtraExtensions, ocspNoCheckExtension)
	}

	return nil
}
