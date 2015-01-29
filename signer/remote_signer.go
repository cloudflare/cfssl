package signer

import (
	"crypto/x509"
	"encoding/json"

	"github.com/cloudflare/cfssl/config"
	cferr "github.com/cloudflare/cfssl/errors"
)

// A RemoteSigner represents a CFSSL instance running as signing server.
// fulfills the Signer interface
type RemoteSigner struct {
	policy *config.Signing
}

// NewRemoteSigner creates a new RemoteSigner directly from a
// signing policy.
func NewRemoteSigner(policy *config.Signing) (*RemoteSigner, error) {
	if policy != nil {
		if !policy.Valid() {
			return nil, cferr.New(cferr.PolicyError,
				cferr.InvalidPolicy)
		}
		return &RemoteSigner{policy: policy}, nil
	}

	return nil, cferr.New(cferr.PolicyError,
		cferr.InvalidPolicy)
}

// Sign sends a signature request to the remote CFSSL server,
// receiving a signed certificate or an error in response. The hostname,
// csr, and profileName are used as with a local signing operation, and
// the label is used to select a signing root in a multi-root CA.
func (s *RemoteSigner) Sign(req SignRequest) (cert []byte, err error) {
	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, cferr.Wrap(cferr.APIClientError, cferr.JSONError, err)
	}

	var profile *config.SigningProfile
	if s.policy.Profiles != nil && req.Profile != "" {
		profile = s.policy.Profiles[req.Profile]
	}

	if profile == nil {
		profile = s.policy.Default
	}

	if profile.Remote == nil {
		return nil, cferr.Wrap(cferr.APIClientError, cferr.JSONError, err)
	}

	if profile.Provider != nil {
		cert, err = profile.Remote.AuthSign(jsonData, nil, profile.Provider)
	} else {
		cert, err = profile.Remote.Sign(jsonData)
	}

	return []byte(cert), nil
}

// SigAlgo returns the RSA signer's signature algorithm.
func (s *RemoteSigner) SigAlgo() x509.SignatureAlgorithm {
	// TODO: implement this as a remote info call
	return x509.UnknownSignatureAlgorithm
}

// Certificate returns the signer's certificate.
func (s *RemoteSigner) Certificate() *x509.Certificate {
	// TODO: implement this as a remote info call
	return nil
}

// SetPolicy sets the signer's signature policy.
func (s *RemoteSigner) SetPolicy(policy *config.Signing) {
	s.policy = policy
}

// Policy returns the signer's policy.
func (s *RemoteSigner) Policy() *config.Signing {
	return s.policy
}
