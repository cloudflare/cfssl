// Package signer implements certificate signature functionality for CF-SSL.
package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"math"
	"math/big"
	"time"

	"github.com/cloudflare/cfssl/config"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
)

// A Signer contains a CA's certificate and private key for signing
// certificates, a Signing policy to refer to and a SignatureAlgorithm
//
type Signer struct {
	CA      *x509.Certificate
	Priv    interface{}
	Policy  *config.Signing
	SigAlgo x509.SignatureAlgorithm
}

// NewSigner generates a new certificate signer using the certificate
// authority certificate and private key and Signing config for signing. caFile should
// contain the CA's certificate, and the cakeyFile should contain the
// private key. Both must be PEM-encoded.
func NewSigner(caFile, cakeyFile string, policy *config.Signing) (*Signer, error) {
	if policy == nil {
		policy = &config.Signing{
			Profiles: map[string]*config.SigningProfile{},
			Default:  config.DefaultConfig(),
		}
	}

	if !policy.Valid() {
		return nil, cferr.New(cferr.PolicyError, cferr.InvalidPolicy, errors.New("invalid policy"))
	}

	log.Debug("Loading CA: ", caFile)
	ca, err := ioutil.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	log.Debug("Loading CA key: ", cakeyFile)
	cakey, err := ioutil.ReadFile(cakeyFile)
	if err != nil {
		return nil, err
	}

	parsedCa, err := helpers.ParseCertificatePEM(ca)
	if err != nil {
		return nil, err
	}

	priv, err := helpers.ParsePrivateKeyPEM(cakey)
	if err != nil {

		return nil, err
	}

	return &Signer{parsedCa, priv, policy, DefaultSigAlgo(priv)}, nil
}

// DefaultSigAlgo returns an appropriate X.509 signature algorithm given the
// CA's private key.
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

func (s *Signer) sign(template *x509.Certificate, profile *config.SigningProfile) (cert []byte, err error) {
	pub := template.PublicKey
	encodedpub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return
	}
	pubhash := sha1.New()
	pubhash.Write(encodedpub)

	if profile == nil {
		profile = s.Policy.Default
	}

	var (
		eku             []x509.ExtKeyUsage
		ku              x509.KeyUsage
		expiry          time.Duration
		crlURL, ocspURL string
	)

	// The third value returned from Usages is a list of unknown key usages.
	// This should be used when validating the profile at load, and isn't used
	// here.
	ku, eku, _ = profile.Usages()
	expiry = profile.Expiry
	if profile.IssuerURL == nil {
		profile.IssuerURL = s.Policy.Default.IssuerURL
	}

	if ku == 0 && len(eku) == 0 {
		err = cferr.New(cferr.PolicyError, cferr.NoKeyUsages, errors.New("no key usage available"))
		return
	}

	if expiry == 0 {
		expiry = s.Policy.Default.Expiry
	}

	if crlURL = profile.CRL; crlURL == "" {
		crlURL = s.Policy.Default.CRL
	}
	if ocspURL = profile.OCSP; ocspURL == "" {
		ocspURL = s.Policy.Default.OCSP
	}

	now := time.Now()
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).SetInt64(math.MaxInt64))
	if err != nil {
		err = cferr.New(cferr.CertificateError, cferr.Unknown, err)
	}

	template.SerialNumber = serialNumber
	template.NotBefore = now.Add(-5 * time.Minute).UTC()
	template.NotAfter = now.Add(expiry).UTC()
	template.KeyUsage = ku
	template.ExtKeyUsage = eku
	template.BasicConstraintsValid = true
	template.IsCA = profile.CA
	template.SubjectKeyId = pubhash.Sum(nil)

	if ocspURL != "" {
		template.OCSPServer = []string{ocspURL}
	}
	if crlURL != "" {
		template.CRLDistributionPoints = []string{crlURL}
	}

	if len(profile.IssuerURL) != 0 {
		template.IssuingCertificateURL = profile.IssuerURL
	}

	var initRoot bool
	if s.CA == nil {
		if !template.IsCA {
			err = cferr.New(cferr.PolicyError, cferr.InvalidRequest, nil)
			return
		}
		template.DNSNames = nil
		s.CA = template
		initRoot = true
		template.MaxPathLen = 2
	} else if template.IsCA {
		template.MaxPathLen = 1
		template.DNSNames = nil
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, s.CA, pub, s.Priv)
	if err != nil {
		return
	}
	if initRoot {
		s.CA, err = x509.ParseCertificate(derBytes)
		if err != nil {
			err = cferr.New(cferr.CertificateError, cferr.ParseFailed, err)
			return
		}
	}
	cert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	return
}

func (s *Signer) parseCertificateRequest(csrBytes []byte) (template *x509.Certificate, err error) {
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		err = cferr.New(cferr.CertificateError, cferr.ParseFailed, err)
		return
	}

	err = checkSignature(csr, csr.SignatureAlgorithm, csr.RawTBSCertificateRequest, csr.Signature)
	if err != nil {
		err = cferr.New(cferr.CertificateError, cferr.KeyMismatch, err)
		return
	}

	template = &x509.Certificate{
		Subject:            csr.Subject,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,
		SignatureAlgorithm: s.SigAlgo,
	}

	return
}

func checkSignature(csr *x509.CertificateRequest, algo x509.SignatureAlgorithm, signed, signature []byte) error {
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

// Sign signs a new certificate based on the PEM-encoded client
// certificate or certificate request with the signing profile, specified by profileName.
// The certificate will be valid for the host named in  the hostName parameter.
func (s *Signer) Sign(hostName string, in []byte, profileName string) (cert []byte, err error) {
	profile := s.Policy.Profiles[profileName]

	block, _ := pem.Decode(in)
	if block == nil {
		return nil, cferr.New(cferr.CertificateError, cferr.DecodeFailed, err)
	}

	var template *x509.Certificate
	switch block.Type {
	case "CERTIFICATE":
		template, err = helpers.ParseSelfSignedCertificatePEM(in)
	case "CERTIFICATE REQUEST":
		template, err = s.parseCertificateRequest(block.Bytes)
	default:
		return nil, cferr.New(cferr.CertificateError, cferr.ParseFailed, errors.New("Not a certificate or csr."))
	}
	if err != nil {
		return
	}

	template.DNSNames = []string{hostName}
	return s.sign(template, profile)
}
