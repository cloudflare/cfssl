package data

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"io/ioutil"
	"time"

	"github.com/cloudflare/cfssl/helpers"
)

// Certificate represents a JSON description of an X.509 certificate.
type Certificate struct {
	RawPEM string `json:"pem"`
	//Certificate *x509.Certificate `json:"cert"`
	SignatureAlgorithm string `json:"sigalg"`
	NotBefore, NotAfter time.Time `json:"notAfter"`
	Subject pkix.Name `json:"subject"`
	SANs []string `json:"sans,omitempty"`
}

// ParseCertificate parses an x509 certificate. 
func ParseCertificate(cert *x509.Certificate) *Certificate {
	c := &Certificate{
		RawPEM: string(helpers.EncodeCertificatePEM(cert)),
		//Certificate: cert,
		SignatureAlgorithm: helpers.SignatureString(cert.SignatureAlgorithm),
		NotBefore: cert.NotBefore,
		NotAfter: cert.NotAfter,
		Subject: cert.Subject,
		SANs: cert.DNSNames,
	}
	for _, ip := range cert.IPAddresses {
		c.SANs = append(c.SANs, ip.String())
	}
	return c
}

// ParseCertificateFile parses x509 certificate file.
func ParseCertificateFile(certFile string) (*Certificate, error) {
	certPEM, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}

	return ParseCertificatePEM(certPEM)
}

// ParseCertificatePEM parses an x509 certificate PEM.
func ParseCertificatePEM(certPEM []byte) (*Certificate, error) {
	cert, err := helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		return nil, err
	}

	return ParseCertificate(cert), nil
}
