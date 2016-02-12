package pkcs11key

import (
	ocsp "github.com/cloudflare/cfssl/ocsp/config"
)

// Config contains configuration information required to use a PKCS
// #11 key.
type Config ocsp.PKCS11Config
