// Package universal implements a signer that can do remote or local
package universal

import (
	"github.com/cloudflare/cfssl/config"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
	"github.com/cloudflare/cfssl/signer/remote"
)

// Root is used to define where the universal signer gets its public
// certificate and private keys for signing.
type Root struct {
	CertFile    string
	KeyFile     string
	ForceRemote bool
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
			// Currently we don't support a hybrid signer
			return nil, cferr.New(cferr.PolicyError, cferr.InvalidPolicy)
		}

		if policy.NeedsLocalSigner() {
			s, err = local.NewSignerFromFile(root.CertFile, root.KeyFile, policy)
		}

		if policy.NeedsRemoteSigner() {
			s, err = remote.NewSigner(policy)
		}
	}

	return s, err
}
