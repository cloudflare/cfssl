package scan

import (
	"github.com/cloudflare/cfssl/certinfo"
	"time"
)

// CTIssuance is the struct that every CertTransparency (CT) family of scanners must return from their scans.
// Every CertIssuance object contains the following fields which are necessary for a CT Report from any API service.
// ID              : Identifier representing the issuance object
// PemCert         : A PEM Encoded Certificate string
// CertType        : A string indicating if the issuance is a "cert" or a "precert"
// NotBefore       : A not before date
// NotAfter        : A not after date
// SerialNumber    : The Certificate serial number
// IssuerCommonName: Common Name of the Issuer
// Cert            : Enabled when verbose, the certinfo breakdown of the PemCert
type CTIssuance struct {
	ID               string                `json:"id"`
	PemCert          string                `json:"pem"`
	CertType         string                `json:"type"`
	NotBefore        time.Time             `json:"not_before"`
	NotAfter         time.Time             `json:"not_after"`
	SerialNumber     string                `json:"serial_number"`
	IssuerCommonName string                `json:"issuer_common_name"`
	Cert             *certinfo.Certificate `json:"cert"`
}

// APIResponseStatus is the struct that every API request for Cert Transparency uses
// to return the status of the API request and the issuance objects.
type APIResponseStatus struct {
	status    bool
	issuances []CTIssuance
	err       error
}

// CertTransparency is a Certificate Transparency Scanner family consisting of multiple Scanners.
var CertTransparency = &Family{
	Description: "Scans Certificate Transparency Servers with the host and reports",
	Scanners: map[string]*Scanner{
		"CertSpotter": {
			"Lookup Domain info in CT Logs from SSL Mate/CertSpotter API Servers",
			CertSpotterScan,
		},
	},
}
