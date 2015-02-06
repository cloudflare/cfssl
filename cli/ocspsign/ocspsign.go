package ocspsign

import (
	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/ocsp"
)

// Usage text of 'cfssl ocspsign'
var ocspSignerUsageText = `cfssl ocspsign -- signs an OCSP response for a given CA, cert, and status"

Usage of ocspsign:
        cfssl ocspsign -ca cert -responder cert -key key -cert cert [-reason code]

Flags:
`

// Flags of 'cfssl ocspsign'
var ocspSignerFlags = []string{"ca", "responder", "key", "reason", "status"}

// ocspSignerFromConfig takes the Config and creates the appropriate
// ocsp.Signer object
func ocspSignerFromConfig(c cli.Config) (ocsp.Signer, error) {
	// TODO pull arguments, assemble an actual signer
	return ocsp.NewSigner(), nil
}

// ocspSignerMain is the main CLI of OCSP signer functionality.
func ocspSignerMain(args []string, c cli.Config) (err error) {
	s, err := ocspSignerFromConfig(c)
	if err != nil {
		log.Critical("Unable to create OCSP signer: ", err)
		return
	}

	req := ocsp.SignRequest{ /* TODO */ }
	resp, err := s.Sign(req)
	if err != nil {
		log.Critical("Unable to sign OCSP response: ", err)
		return
	}

	cli.PrintOcspResponse(resp)
	return
}

// CLISigner assembles the definition of Command 'sign'
var Command = &cli.Command{UsageText: ocspSignerUsageText, Flags: ocspSignerFlags, Main: ocspSignerMain}
