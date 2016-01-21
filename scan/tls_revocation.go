package scan

import (
	"crypto/tls"
	"crypto/x509"

	"golang.org/x/crypto/ocsp"
)

// TLSRevocation contains scanners testing certificate revocation.
var TLSRevocation = &Family{
	Description: "Scans determining certificate revocation",
	Scanners: map[string]*Scanner{
		"OCSPStaple": {
			"Checks OCSP Staple if given",
			ocspStapleScan,
		},
	},
}

// ocspStapleScan checks the hosts OSCP staple if one is returned.
func ocspStapleScan(addr, hostname string) (grade Grade, output Output, err error) {
	conn, err := tls.DialWithDialer(Dialer, Network, addr, &tls.Config{
		ServerName: hostname,
		RootCAs:    RootCAs,
	})
	if err != nil {
		return
	}
	conn.Close()

	connState := conn.ConnectionState()

	if len(connState.OCSPResponse) == 0 {
		grade = Warning
		return
	}

	var issuer *x509.Certificate
	if len(connState.PeerCertificates) > 1 {
		issuer = connState.PeerCertificates[1]
	}

	resp, err := ocsp.ParseResponse(connState.OCSPResponse, issuer)
	if resp.Status == ocsp.Good {
		grade = Good
	}
	output = resp
	return
}
