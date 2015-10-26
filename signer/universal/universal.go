// Package universal implements a signer that can do remote or local
package universal

import (
	"crypto/x509"

	"github.com/cloudflare/cfssl/config"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/info"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
	"github.com/cloudflare/cfssl/signer/pkcs11"
	"github.com/cloudflare/cfssl/signer/remote"
)

// Signer represents a universal signer which is both local and remote
// to fulfill the signer.Signer interface.
type Signer struct {
	local  signer.Signer
	remote signer.Signer
	policy *config.Signing
}

// Root is used to define where the universal signer gets its public
// certificate and private keys for signing.
type Root struct {
	Config      map[string]string
	ForceRemote bool
}

// a localSignerCheck looks at the Config keys in the Root, and
// decides whether it has enough information to produce a signer.
type localSignerCheck func(root *Root, policy *config.Signing) (signer.Signer, bool, error)

// fileBackedSigner determines whether a file-backed local signer is supported.
func fileBackedSigner(root *Root, policy *config.Signing) (signer.Signer, bool, error) {
	keyFile := root.Config["key-file"]
	certFile := root.Config["cert-file"]

	if keyFile == "" {
		return nil, false, nil
	}

	signer, err := local.NewSignerFromFile(certFile, keyFile, policy)
	return signer, true, err
}

// pkcs11Signer looks for token, module, slot, and PIN configuration
// options in the root.
func pkcs11Signer(root *Root, policy *config.Signing) (signer.Signer, bool, error) {
	module := root.Config["pkcs11-module"]
	tokenLabel := root.Config["pkcs11-token-label"]
	privateKeyLabel := root.Config["pkcs11-private-key-label"]
	userPIN := root.Config["pkcs11-user-pin"]
	certFile := root.Config["cert-file"]

	if module == "" && tokenLabel == "" && privateKeyLabel == "" && userPIN == "" {
		return nil, false, nil
	}

	if !pkcs11.Enabled {
		return nil, true, cferr.New(cferr.PrivateKeyError, cferr.Unavailable)
	}

	conf := pkcs11.Config{
		Module: module,
		Token:  tokenLabel,
		Label:  privateKeyLabel,
		PIN:    userPIN,
	}

	s, err := pkcs11.New(certFile, policy, &conf)
	return s, true, err
}

var localSignerList = []localSignerCheck{
	pkcs11Signer,
	fileBackedSigner,
}

func newLocalSigner(root Root, policy *config.Signing) (s signer.Signer, err error) {
	// shouldProvide indicates whether the
	// function *should* have produced a key. If
	// it's true, we should use the signer and
	// error returned. Otherwise, keep looking for
	// signers.
	var shouldProvide bool

	// localSignerList is defined in the
	// universal_signers*.go files. These activate
	// and deactivate signers based on build
	// flags; for example,
	// universal_signers_pkcs11.go contains a list
	// of valid signers when PKCS #11 is turned
	// on.
	for _, possibleSigner := range localSignerList {
		s, shouldProvide, err = possibleSigner(&root, policy)
		if shouldProvide {
			break
		}
	}

	if s == nil {
		err = cferr.New(cferr.PrivateKeyError, cferr.Unknown)
	}

	return s, err
}

func newUniversalSigner(root Root, policy *config.Signing) (*Signer, error) {
	ls, err := newLocalSigner(root, policy)
	if err != nil {
		return nil, err
	}

	rs, err := remote.NewSigner(policy)

	s := &Signer{
		policy: policy,
		local:  ls,
		remote: rs,
	}
	return s, err
}

// NewSigner generates a new certificate signer from a Root structure.
// This is one of two standard signers: local or remote. If the root
// structure specifies a force remote, then a remote signer is created,
// otherwise either a remote or local signer is generated based on the
// policy. For a local signer, the CertFile and KeyFile need to be
// defined in Root.
func NewSigner(root Root, policy *config.Signing) (signer.Signer, error) {
	if policy == nil {
		policy = &config.Signing{
			Profiles: map[string]*config.SigningProfile{},
			Default:  config.DefaultConfig(),
		}
	}

	if !policy.Valid() {
		return nil, cferr.New(cferr.PolicyError, cferr.InvalidPolicy)
	}

	var s signer.Signer
	var err error
	if root.ForceRemote {
		s, err = remote.NewSigner(policy)
	} else {
		if policy.NeedsLocalSigner() && policy.NeedsRemoteSigner() {
			s, err = newUniversalSigner(root, policy)
		} else {
			if policy.NeedsLocalSigner() {
				s, err = newLocalSigner(root, policy)
			}
			if policy.NeedsRemoteSigner() {
				s, err = remote.NewSigner(policy)
			}
		}
	}

	return s, err
}

// getMatchingProfile returns the SigningProfile that matches the profile passed.
func (s *Signer) getMatchingProfile(profile string) (*config.SigningProfile, error) {
	for p, signingProfile := range s.policy.Profiles {
		if p == profile {
			return signingProfile, nil
		}
	}

	return nil, cferr.New(cferr.PolicyError, cferr.UnknownProfile)
}

// Sign sends a signature request to either the remote or local signer,
// receiving a signed certificate or an error in response.
func (s *Signer) Sign(req signer.SignRequest) (cert []byte, err error) {
	profile, err := s.getMatchingProfile(req.Profile)
	if err != nil {
		return cert, err
	}

	if profile.RemoteServer != "" {
		return s.remote.Sign(req)
	}
	return s.local.Sign(req)

}

// Info sends an info request to the remote or local CFSSL server
// receiving an Resp struct or an error in response.
func (s *Signer) Info(req info.Req) (resp *info.Resp, err error) {
	profile, err := s.getMatchingProfile(req.Profile)
	if err != nil {
		return resp, err
	}

	if profile.RemoteServer != "" {
		return s.remote.Info(req)
	}
	return s.local.Info(req)

}

// SigAlgo returns the RSA signer's signature algorithm.
func (s *Signer) SigAlgo() x509.SignatureAlgorithm {
	if s.local != nil {
		return s.local.SigAlgo()
	}

	// currently remote.SigAlgo just returns
	// x509.UnknownSignatureAlgorithm.
	return s.remote.SigAlgo()
}

// SetPolicy sets the signer's signature policy.
func (s *Signer) SetPolicy(policy *config.Signing) {
	s.policy = policy
}

// Policy returns the signer's policy.
func (s *Signer) Policy() *config.Signing {
	return s.policy
}
