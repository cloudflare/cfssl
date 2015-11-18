// +build !ctclient

package ctclient

import (
	"crypto/x509"

	"github.com/cloudflare/cfssl/errors"
)

// GetSCTList always returns an error. If certificate transparency support is needed, the
// program should be built with the `ctclient` build tag.
func GetSCTList(cert []byte, caCert x509.Certificate, logServers []string) (serializedSCTList []byte, err error) {
	return nil, errors.New(errors.CTError, errors.Unknown)
}
