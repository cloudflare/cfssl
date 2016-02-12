// +build nopkcs11 appengine

package pkcs11

import (
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/signer"
)

// New always returns an error. If PKCS #11 support is needed, the
// program should be built with the `pkcs11` build tag.
func New(caCertFile string, policy *config.Signing, cfg *Config) (signer.Signer, error) {
	return nil, errors.New(errors.PrivateKeyError, errors.Unknown)
}

// Enabled is set to true if PKCS #11 support is present.
const Enabled = false
