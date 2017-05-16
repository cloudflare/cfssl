package fixchain

import (
	"encoding/pem"
	"errors"

	"github.com/google/certificate-transparency-go/x509"
)

// CertificateFromPEM takes a string representing a certificate in PEM format
// and returns the corresponding x509.Certificate object.
func CertificateFromPEM(pemBytes string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemBytes))
	if block == nil {
		return nil, errors.New("failed to decode PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}
