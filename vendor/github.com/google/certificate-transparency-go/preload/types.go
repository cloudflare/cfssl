package preload

import (
	ct "github.com/google/certificate-transparency-go"
)

// AddedCert holds information about a certificate that has been added to a log.
type AddedCert struct {
	CertDER                    ct.ASN1Cert
	SignedCertificateTimestamp ct.SignedCertificateTimestamp
	AddedOk                    bool
	ErrorMessage               string
}
