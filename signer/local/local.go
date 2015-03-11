// Package local implements certificate signature functionality for CF-SSL.
package local

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"

	"github.com/cloudflare/cfssl/config"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
)

// Signer contains a signer that uses the standard library to
// support both ECDSA and RSA CA keys.
type Signer struct {
	ca      *x509.Certificate
	priv    crypto.Signer
	policy  *config.Signing
	sigAlgo x509.SignatureAlgorithm
}

// NewSigner creates a new Signer directly from a
// private key and certificate, with optional policy.
func NewSigner(priv crypto.Signer, cert *x509.Certificate, sigAlgo x509.SignatureAlgorithm, policy *config.Signing) (*Signer, error) {
	if policy == nil {
		policy = &config.Signing{
			Profiles: map[string]*config.SigningProfile{},
			Default:  config.DefaultConfig()}
	}

	if !policy.Valid() {
		return nil, cferr.New(cferr.PolicyError, cferr.InvalidPolicy)
	}

	return &Signer{
		ca:      cert,
		priv:    priv,
		sigAlgo: sigAlgo,
		policy:  policy,
	}, nil
}

// NewSignerFromFile generates a new local signer from a caFile
// and a caKey file, both PEM encoded.
func NewSignerFromFile(caFile, caKeyFile string, policy *config.Signing) (*Signer, error) {
	log.Debug("Loading CA: ", caFile)
	ca, err := ioutil.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	log.Debug("Loading CA key: ", caKeyFile)
	cakey, err := ioutil.ReadFile(caKeyFile)
	if err != nil {
		return nil, cferr.Wrap(cferr.CertificateError, cferr.ReadFailed, err)
	}

	parsedCa, err := helpers.ParseCertificatePEM(ca)
	if err != nil {
		return nil, err
	}

	priv, err := helpers.ParsePrivateKeyPEM(cakey)
	if err != nil {
		log.Debug("Malformed private key %v", err)
		return nil, err
	}

	return NewSigner(priv, parsedCa, signer.DefaultSigAlgo(priv), policy)
}

func (s *Signer) sign(template *x509.Certificate, profile *config.SigningProfile) (cert []byte, err error) {
	err = signer.FillTemplate(template, s.policy.Default, profile)
	if err != nil {
		return
	}

	serialNumber := template.SerialNumber
	var initRoot bool
	if s.ca == nil {
		if !template.IsCA {
			err = cferr.New(cferr.PolicyError, cferr.InvalidRequest)
			return
		}
		template.DNSNames = nil
		s.ca = template
		initRoot = true
		template.MaxPathLen = signer.MaxPathLen
	} else if template.IsCA {
		template.MaxPathLen = 1
		template.DNSNames = nil
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, s.ca, template.PublicKey, s.priv)
	if err != nil {
		return
	}
	if initRoot {
		s.ca, err = x509.ParseCertificate(derBytes)
		if err != nil {
			err = cferr.Wrap(cferr.CertificateError, cferr.ParseFailed, err)
			return
		}
	}

	cert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	log.Infof("signed certificate with serial number %s", serialNumber)
	return
}

// Sign signs a new certificate based on the PEM-encoded client
// certificate or certificate request with the signing profile,
// specified by profileName.
func (s *Signer) Sign(req signer.SignRequest) (cert []byte, err error) {
	profile := s.policy.Profiles[req.Profile]
	if profile == nil {
		profile = s.policy.Default
	}

	block, _ := pem.Decode([]byte(req.Request))
	if block == nil {
		return nil, cferr.New(cferr.CertificateError, cferr.DecodeFailed)
	}

	if block.Type != "CERTIFICATE REQUEST" {
		return nil, cferr.Wrap(cferr.CertificateError,
			cferr.BadRequest, errors.New("not a certificate or csr"))
	}

	template, err := signer.ParseCertificateRequest(s, block.Bytes, req.Subject, req.Hosts)
	if err != nil {
		return nil, err
	}

	return s.sign(template, profile)
}

// SigAlgo returns the RSA signer's signature algorithm.
func (s *Signer) SigAlgo() x509.SignatureAlgorithm {
	return s.sigAlgo
}

// Certificate returns the signer's certificate.
func (s *Signer) Certificate(label, profile string) (*x509.Certificate, error) {
	if label != "" {
		return nil, cferr.NewBadRequestString("label specified for local operation")
	}
	cert := *s.ca
	return &cert, nil
}

// SetPolicy sets the signer's signature policy.
func (s *Signer) SetPolicy(policy *config.Signing) {
	s.policy = policy
}

// Policy returns the signer's policy.
func (s *Signer) Policy() *config.Signing {
	return s.policy
}
