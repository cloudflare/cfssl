// Package revoke implements the revoke command.
package revoke

import (
	goerr "errors"
	"strconv"
	"strings"

	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/ocsp"
	"github.com/cloudflare/cfssl/certdb"
)

var revokeUsageTxt = `cfssl revoke -- revoke a certificate in the certificate store

Usage:

Revoke a certificate:
	   cfssl revoke -serial serial [-reason reason]

Reason can be an integer code or a string in ReasonFlags in RFC 5280

Flags:
`

var revokeFlags = []string{"serial", "reason"}

func revokeMain(args []string, c cli.Config) (err error) {
	if len(args) > 0 {
		return goerr.New("argument is provided but not defined; please refer to the usage by flag -h.")
	}

	if len(c.Serial) == 0 {
		return goerr.New("serial number is required but not provided")
	}

	reasonCode, present := ocsp.RevocationReasonCodes[strings.ToLower(c.Reason)]
	if !present {
		reasonCode, err = strconv.Atoi(c.Reason)
		if err != nil {
			return
		}
	}

	err = certdb.RevokeCert(c.Serial, reasonCode)

	return
}

// Command assembles the definition of Command 'revoke'
var Command = &cli.Command{
	UsageText: revokeUsageTxt,
	Flags:     revokeFlags,
	Main:      revokeMain,
}
