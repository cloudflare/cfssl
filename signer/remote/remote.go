package remote

import (
	"crypto/x509"
	"encoding/json"
	"errors"

	"github.com/cloudflare/cfssl/api/client"
	"github.com/cloudflare/cfssl/config"
	cferr "github.com/cloudflare/cfssl/errors"
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

	server := client.NewServer(profile.RemoteName)
	if server == nil {
		return nil, cferr.Wrap(cferr.PolicyError, cferr.InvalidRequest,
			errors.New("failed to connect to remote"))
	}

	if server == nil {
		return nil, cferr.Wrap(cferr.APIClientError, cferr.JSONError, err)
	}

	if profile.Provider != nil {
		cert, err = server.AuthSign(jsonData, nil, profile.Provider)
	} else {
		cert, err = server.Sign(jsonData)
	}

	return []byte(cert), nil
}

// SigAlgo returns the RSA signer's signature algorithm.
func (s *Signer) SigAlgo() x509.SignatureAlgorithm {
	// TODO: implement this as a remote info call
	return x509.UnknownSignatureAlgorithm
}

// Certificate returns the signer's certificate.
func (s *Signer) Certificate() *x509.Certificate {
	// TODO: implement this as a remote info call
	return nil
}

// SetPolicy sets the signer's signature policy.
func (s *Signer) SetPolicy(policy *config.Signing) {
	s.policy = policy
}

// Policy returns the signer's policy.
func (s *Signer) Policy() *config.Signing {
	return s.policy
}
