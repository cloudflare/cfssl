// Package revoke implements the revoke command.
package revoke

import (
	"database/sql"
	"errors"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/ocsp"
)

var revokeUsageTxt = `cfssl revoke -- revoke a certificate in the certificate store

Usage:

Revoke a certificate:
	   cfssl revoke -db-config config_file -serial serial [-reason reason]

Reason can be an integer code or a string in ReasonFlags in RFC 5280

Flags:
`

var revokeFlags = []string{"serial", "reason"}

func revokeMain(args []string, c cli.Config) (err error) {
	if len(args) > 0 {
		return errors.New("argument is provided but not defined; please refer to the usage by flag -h")
	}

	if len(c.Serial) == 0 {
		return errors.New("serial number is required but not provided")
	}

	if c.DBConfigFile == "" {
		return errors.New("need DB config file (provide with -db-config)")
	}

	var db *sql.DB
	db, err = certdb.DBFromConfig(c.DBConfigFile)
	if err != nil {
		return err
	}

	var reasonCode int
	reasonCode, err = ocsp.ReasonStringToCode(c.Reason)
	if err != nil {
		log.Error("Invalid reason code: ", err)
		return
	}

	err = certdb.RevokeCertificate(db, c.Serial, reasonCode)

	return
}

// Command assembles the definition of Command 'revoke'
var Command = &cli.Command{
	UsageText: revokeUsageTxt,
	Flags:     revokeFlags,
	Main:      revokeMain,
}
