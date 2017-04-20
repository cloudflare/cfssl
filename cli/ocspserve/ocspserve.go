// Package ocspserve implements the ocspserve function.
package ocspserve

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/ocsp"
)

// Usage text of 'cfssl serve'
var ocspServerUsageText = `cfssl ocspserve -- set up an HTTP server that handles OCSP requests from a file (see RFC 5019)

  Usage of ocspserve:
          cfssl ocspserve [-address address] [-port port] [-responses file]

  Flags:
  `

// Flags used by 'cfssl serve'
var ocspServerFlags = []string{"address", "port", "responses"}

// ocspServerMain is the command line entry point to the OCSP responder.
// It sets up a new HTTP server that responds to OCSP requests.
func ocspServerMain(args []string, c cli.Config) error {
	// serve doesn't support arguments.
	if len(args) > 0 {
		return errors.New("argument is provided but not defined; please refer to the usage by flag -h")
	}

	if c.Responses == "" {
		return errors.New("no response file provided, please set the -responses flag")
	}

	typ, path, err := helpers.ParseConnectionStr(c.Responses)
	if err != nil {
		return errors.New("unable to parse responses connection string")
	}
	switch typ {
	case "file":
		src, err := ocsp.NewSourceFromFile(path)
		if err != nil {
			return errors.New("unable to read response file")
		}
	case "sqlite":
		src, err := ocsp.NewSqliteSource(path)
		if err != nil {
			return errors.New("unable to read Sqlite connection string")
		}
	case "mysql":
		src, err := ocsp.NewMySQLSource(path)
		if err != nil {
			return errors.New("unable to read MySQL connection string")
		}
	case "postgres":
		src, err := ocsp.NewPostgresSource(path)
		if err != nil {
			return errors.New("unable to read PostgreSQL connection string")
		}
	default:
		// TODO: I can probably to something more intelligent here
		return errors.New("not sure what to do in this case")
	}

	log.Info("Registering OCSP responder handler")
	http.Handle(c.Path, ocsp.NewResponder(src))

	addr := fmt.Sprintf("%s:%d", c.Address, c.Port)
	log.Info("Now listening on ", addr)
	return http.ListenAndServe(addr, nil)
}

// Command assembles the definition of Command 'ocspserve'
var Command = &cli.Command{UsageText: ocspServerUsageText, Flags: ocspServerFlags, Main: ocspServerMain}
