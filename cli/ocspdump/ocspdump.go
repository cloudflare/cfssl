// Package ocspdump implements the ocspdump command.
package ocspdump

import (
	"database/sql"
	"encoding/base64"
	"fmt"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/log"
)

// Usage text of 'cfssl ocspdump'
var ocspdumpUsageText = `cfssl ocspdump -- generates a series of concatenated OCSP responses
for use with ocspserve from all OCSP responses in the cert db

Usage of ocspdump:
        cfssl ocspdump -db-config db-config

Flags:
`

// Flags of 'cfssl ocspdump'
var ocspdumpFlags = []string{"db-config"}

// ocspdumpMain is the main CLI of OCSP dump functionality.
func ocspdumpMain(args []string, c cli.Config) (err error) {
	if c.DBConfigFile == "" {
		log.Error("need DB config file (provide with -db-config)")
		return
	}

	var db *sql.DB
	db, err = certdb.DBFromConfig(c.DBConfigFile)
	if err != nil {
		return err
	}

	var records []*certdb.OCSPRecord
	records, err = certdb.GetUnexpiredOCSPs(db)
	if err != nil {
		return err
	}
	for _, certRecord := range records {
		fmt.Printf("%s\n", base64.StdEncoding.EncodeToString([]byte(certRecord.Body)))
	}
	return nil
}

// Command assembles the definition of Command 'ocspdump'
var Command = &cli.Command{UsageText: ocspdumpUsageText, Flags: ocspdumpFlags, Main: ocspdumpMain}
