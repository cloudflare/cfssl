package remote

import (
	"crypto/x509"
	"encoding/json"
	"errors"

	"github.com/cloudflare/cfssl/api/client"
	"github.com/cloudflare/cfssl/config"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/signer"
)

// A Signer represents a CFSSL instance running as signing server.
// fulfills the signer.Signer interface
type Signer struct {
	policy *config.Signing
}

// NewSigner creates a new remote Signer directly from a
// signing policy.
func NewSigner(policy *config.Signing) (*Signer, error) {
	if policy != nil {
		if !policy.Valid() {
			return nil, cferr.New(cferr.PolicyError,
				cferr.InvalidPolicy)
		}
		return &Signer{policy: policy}, nil
	}

	return nil, cferr.New(cferr.PolicyError,
		cferr.InvalidPolicy)
}

// Sign sends a signature request to the remote CFSSL server,
// receiving a signed certificate or an error in response. The hostname,
// csr, and profileName are used as with a local signing operation, and
// the label is used to select a signing root in a multi-root CA.
func (s *Signer) Sign(req signer.SignRequest) (cert []byte, err error) {
	return s.remoteOp(req, req.Profile, "sign")
}

// Info sends an info request to the remote CFSSL server, receiving a signed
// certificate or an error in response.
func (s *Signer) Info(req client.InfoReq) (cert []byte, err error) {
	return s.remoteOp(req, req.Profile, "info")
}

// Helper function to perform a remote sign or info request.
func (s *Signer) remoteOp(req interface{}, profile, target string) (cert []byte, err error) {
	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, cferr.Wrap(cferr.APIClientError, cferr.JSONError, err)
	}

	var p *config.SigningProfile
	if s.policy.Profiles != nil && profile != "" {
		p = s.policy.Profiles[profile]
	}

	if p == nil {
		p = s.policy.Default
	}

	server := client.NewServer(p.RemoteServer)
	if server == nil {
		return nil, cferr.Wrap(cferr.PolicyError, cferr.InvalidRequest,
			errors.New("failed to connect to remote"))
	}

	if p.Provider != nil {
		cert, err = server.AuthReq(jsonData, nil, p.Provider, target)
	} else {
		cert, err = server.Req(jsonData, target)
	}

	if err != nil {
		return nil, err
	}

	return []byte(cert), nil
}

// SigAlgo returns the RSA signer's signature algorithm.
func (s *Signer) SigAlgo() x509.SignatureAlgorithm {
	// TODO: implement this as a remote info call
	return x509.UnknownSignatureAlgorithm
}

// Certificate returns the signer's certificate.
func (s *Signer) Certificate(label, profile string) (*x509.Certificate, error) {
	certStr, err := s.Info(client.InfoReq{Label: label, Profile: profile})
	if err != nil {
		return nil, err
	}
	cert, err := helpers.ParseCertificatePEM(certStr)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// SetPolicy sets the signer's signature policy.
func (s *Signer) SetPolicy(policy *config.Signing) {
	s.policy = policy
}

// Policy returns the signer's policy.
func (s *Signer) Policy() *config.Signing {
	return s.policy
}
