// Package ocspgen implements the ocspgen command.
package ocspgen

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/ocsp"
)

// Usage text of 'cfssl ocspgen'
var ocspgenUsageText = `cfssl ocspgen -- generates a series of concatenated OCSP responses
for use with ocspserve from all unexpired certs in the cert store

Usage of ocspgen:
        cfssl ocspgen -ca cert -responder cert -responder-key key

Flags:
`

// Flags of 'cfssl ocspgen'
var ocspgenFlags = []string{"ca", "responder", "responder-key"}

// ocspgenMain is the main CLI of OCSP generation functionality.
func ocspgenMain(args []string, c cli.Config) (err error) {
	var certs []certdb.CertificateRecord
	certs, err = certdb.GetUnexpiredCertificateRecords()
	if err != nil {
		return err
	}
	for _, certRecord := range certs {
		cert, err := helpers.ParseCertificatePEM([]byte(certRecord.PEM))
		if err != nil {
			log.Critical("Unable to parse certificate: ", err)
			return err
		}

		req := ocsp.SignRequest{
			Certificate: cert,
			Status:      c.Status,
		}

		if certRecord.RevokedAt != nil {
			req.Reason = int(certRecord.Reason)
			req.RevokedAt = *certRecord.RevokedAt
		}

		s, err := SignerFromConfig(c)
		if err != nil {
			log.Critical("Unable to create OCSP signer: ", err)
			return err
		}

		resp, err := s.Sign(req)
		if err != nil {
			log.Critical("Unable to sign OCSP response: ", err)
			return err
		}
		fmt.Printf("%s\n", base64.StdEncoding.EncodeToString(resp))
	}
	return nil
}

// SignerFromConfig creates a signer from a cli.Config as a helper for cli and serve
func SignerFromConfig(c cli.Config) (ocsp.Signer, error) {
	//if this is called from serve then we need to use the specific responder key file
	//fallback to key for backwards-compatibility
	k := c.ResponderKeyFile
	if k == "" {
		k = c.KeyFile
	}
	return ocsp.NewSignerFromFile(c.CAFile, c.ResponderFile, k, time.Duration(c.Interval))
}

// Command assembles the definition of Command 'ocspgen'
var Command = &cli.Command{UsageText: ocspgenUsageText, Flags: ocspgenFlags, Main: ocspgenMain}
