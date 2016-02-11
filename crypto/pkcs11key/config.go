package pkcs11key

import (
	OcspConfig "github.com/cloudflare/cfssl/ocsp/config"
)

// Config contains configuration information required to use a PKCS
// #11 key.
type Config struct {
	OcspConfig.PKCS11Config
}
