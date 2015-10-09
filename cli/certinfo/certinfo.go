// Package certinfo implements the certinfo command
package certinfo

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cloudflare/cfssl/certinfo"
	"github.com/cloudflare/cfssl/cli"
)

// Usage text of 'cfssl certinfo'
var dataUsageText = `cfssl certinfo -- output certinfo about the given cert

Usage of certinfo:
	- Data from local certificate files
        cfssl certinfo -cert file
	- Data from certificate from remote server.
        cfssl certinfo -domain domain_name

Flags:
`

// flags used by 'cfssl certinfo'
var certinfoFlags = []string{"cert", "domain"}

// certinfoMain is the main CLI of certinfo functionality
func certinfoMain(args []string, c cli.Config) (err error) {
	var cert *certinfo.Certificate

	if c.CertFile != "" {
		if c.CertFile == "-" {
			var certPEM []byte
			if certPEM, err = cli.ReadStdin(c.CertFile); err != nil {
				return
			}

			if cert, err = certinfo.ParseCertificatePEM(certPEM); err != nil {
				return
			}
		} else {
			if cert, err = certinfo.ParseCertificateFile(c.CertFile); err != nil {
				return
			}
		}
	} else if c.Domain != "" {
		if cert, err = certinfo.ParseCertificateDomain(c.Domain); err != nil {
			return
		}
	} else {
		return errors.New("Must specify certinfo target through -cert or -domain")
	}

	var b []byte
	b, err = json.MarshalIndent(cert, "", "  ")
	if err != nil {
		return
	}

	fmt.Println(string(b))
	return
}

// Command assembles the definition of Command 'bundle'
var Command = &cli.Command{UsageText: dataUsageText, Flags: certinfoFlags, Main: certinfoMain}
