// +build !pkcs11

package pkcs11

import (
	"github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/ocsp"
	ocspConfig "github.com/cloudflare/cfssl/ocsp/config"
)

// Enabled is set to true if PKCS #11 support is present.
const Enabled = false

// NewPKCS11Signer returns a new PKCS #11 signer.
func NewPKCS11Signer(cfg ocspConfig.Config) (ocsp.Signer, error) {
	return nil, errors.New(errors.PrivateKeyError, errors.Unavailable)
}
