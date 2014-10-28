// Package signer implements certificate signature functionality for CF-SSL.
package signer

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"math"
	"math/big"
	"net"
	"time"

	"github.com/cloudflare/cfssl/config"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
)

// MaxPathLen is the default path length for a new CA certificate.
var MaxPathLen = 2

// StandardSigner contains a signer that uses the standard library to
// support both ECDSA and RSA CA keys.
type StandardSigner struct {
	ca      *x509.Certificate
	priv    interface{}
	policy  *config.Signing
	sigAlgo x509.SignatureAlgorithm
}

// NewStandardSigner creates a new StandardSigner directly from a
// private key and certificate.
func NewStandardSigner(priv interface{}, cert *x509.Certificate, sigAlgo x509.SignatureAlgorithm) *StandardSigner {
	return &StandardSigner{
		ca:      cert,
		priv:    priv,
		sigAlgo: sigAlgo,
		policy: &config.Signing{
			Profiles: map[string]*config.SigningProfile{},
			Default:  config.DefaultConfig(),
		},
	}
}

// NewSigner generates a new standard library certificate signer using
// the certificate authority certificate and private key and Signing
// config for signing. caFile should contain the CA's certificate, and
// the cakeyFile should contain the private key. Both must be
// PEM-encoded.
func NewSigner(caFile, cakeyFile string, policy *config.Signing) (*StandardSigner, error) {
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

	return &StandardSigner{parsedCa, priv, policy, DefaultSigAlgo(priv)}, nil
}

type subjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

func (s *StandardSigner) sign(template *x509.Certificate, profile *config.SigningProfile) (cert []byte, err error) {
	pub := template.PublicKey
	encodedpub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return
	}
	var subPKI subjectPublicKeyInfo
	_, err = asn1.Unmarshal(encodedpub, &subPKI)
	if err != nil {
		return
	}

	pubhash := sha1.New()
	pubhash.Write(subPKI.SubjectPublicKey.Bytes)

	if profile == nil {
		profile = s.policy.Default
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
		profile.IssuerURL = s.policy.Default.IssuerURL
	}

	if ku == 0 && len(eku) == 0 {
		err = cferr.New(cferr.PolicyError, cferr.NoKeyUsages, errors.New("no key usage available"))
		return
	}

	if expiry == 0 {
		expiry = s.policy.Default.Expiry
	}

	if crlURL = profile.CRL; crlURL == "" {
		crlURL = s.policy.Default.CRL
	}
	if ocspURL = profile.OCSP; ocspURL == "" {
		ocspURL = s.policy.Default.OCSP
	}

	now := time.Now()
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).SetInt64(math.MaxInt64))
	if err != nil {
		err = cferr.New(cferr.CertificateError, cferr.Unknown, err)
		return
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
	if s.ca == nil {
		if !template.IsCA {
			err = cferr.New(cferr.PolicyError, cferr.InvalidRequest, nil)
			return
		}
		template.DNSNames = nil
		s.ca = template
		initRoot = true
		template.MaxPathLen = MaxPathLen
	} else if template.IsCA {
		template.MaxPathLen = 1
		template.DNSNames = nil
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, s.ca, pub, s.priv)
	if err != nil {
		return
	}
	if initRoot {
		s.ca, err = x509.ParseCertificate(derBytes)
		if err != nil {
			err = cferr.New(cferr.CertificateError, cferr.ParseFailed, err)
			return
		}
	}
	cert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	log.Infof("Signed certificate with serial number %s", serialNumber)
	return
}

// Sign signs a new certificate based on the PEM-encoded client
// certificate or certificate request with the signing profile, specified
// by profileName. The certificate will be valid for the host named in
// the hostName parameter. If not nil, the subject information contained
// in subject will be used in place of the subject information in the CSR.
func (s *StandardSigner) Sign(hostName string, in []byte, subject *Subject, profileName string) (cert []byte, err error) {
	profile := s.policy.Profiles[profileName]

	block, _ := pem.Decode(in)
	if block == nil {
		return nil, cferr.New(cferr.CertificateError, cferr.DecodeFailed, err)
	}

	if block.Type != "CERTIFICATE REQUEST" {
		return nil, cferr.New(cferr.CertificateError,
			cferr.ParseFailed, errors.New("not a certificate or csr"))
	}

	template, err := ParseCertificateRequest(s, block.Bytes, subject)
	if err != nil {
		return
	}

	if subject == nil {
		if ip := net.ParseIP(hostName); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, hostName)
		}
	} else {
		template.DNSNames = []string{}
		template.IPAddresses = []net.IP{}
		for _, host := range subject.Hosts {
			if ip := net.ParseIP(host); ip != nil {
				template.IPAddresses = append(template.IPAddresses, ip)
			} else {
				template.DNSNames = append(template.DNSNames, host)
			}
		}
	}
	return s.sign(template, profile)
}

// SigAlgo returns the RSA signer's signature algorithm.
func (s *StandardSigner) SigAlgo() x509.SignatureAlgorithm {
	return s.sigAlgo
}

// Certificate returns the signer's certificate.
func (s *StandardSigner) Certificate() *x509.Certificate {
	cert := *s.ca
	return &cert
}

// SetPolicy sets the signer's signature policy.
func (s *StandardSigner) SetPolicy(policy *config.Signing) {
	s.policy = policy
}

// Policy returns the signer's policy.
func (s *StandardSigner) Policy() *config.Signing {
	return s.policy
}
