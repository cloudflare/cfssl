// Package serve implements the serve command for CFSSL's API.
package serve

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/cloudflare/cfssl/api/bundle"
	"github.com/cloudflare/cfssl/api/generator"
	"github.com/cloudflare/cfssl/api/info"
	"github.com/cloudflare/cfssl/api/initca"
	"github.com/cloudflare/cfssl/api/scan"
	apisign "github.com/cloudflare/cfssl/api/sign"
	"github.com/cloudflare/cfssl/bundler"
	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/cli/sign"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/ubiquity"
)

// Usage text of 'cfssl serve'
var serverUsageText = `cfssl serve -- set up a HTTP server handles CF SSL requests

Usage of serve:
        cfssl serve [-address address] [-ca cert] [-ca-bundle bundle] \
                    [-ca-key key] [-int-bundle bundle] [-port port] [-metadata file] \
                    [-remote remote_host] [-config config]

Flags:
`

// Flags used by 'cfssl serve'
var serverFlags = []string{"address", "port", "ca", "ca-key", "ca-bundle", "int-bundle", "int-dir", "metadata", "remote", "config"}

// registerHandlers instantiates various handlers and associate them to corresponding endpoints.
func registerHandlers(c cli.Config) error {
	log.Info("Setting up signer endpoint")
	s, err := sign.SignerFromConfig(c)
	if err != nil {
		log.Warningf("sign and authsign endpoints are disabled: %v", err)
	} else {
		if signHandler, err := apisign.NewHandlerFromSigner(s); err == nil {
			log.Info("Assigning handler to /sign")
			http.Handle("/api/v1/cfssl/sign", signHandler)
		} else {
			log.Warningf("endpoint '/api/v1/cfssl/sign' is disabled: %v", err)
		}

		if signHandler, err := apisign.NewAuthHandlerFromSigner(s); err == nil {
			log.Info("Assigning handler to /authsign")
			http.Handle("/api/v1/cfssl/authsign", signHandler)
		} else {
			log.Warningf("endpoint '/api/v1/cfssl/authsign' is disabled: %v", err)
		}
	}

	log.Info("Setting up info endpoint")
	infoHandler, err := info.NewHandler(s)
	if err != nil {
		log.Warningf("endpoint '/api/v1/cfssl/info' is disabled: %v", err)
	} else {
		http.Handle("/api/v1/cfssl/info", infoHandler)
	}

	log.Info("Setting up new cert endpoint")
	if err != nil {
		log.Errorf("endpoint '/api/v1/cfssl/newcert' is disabled")
	} else {
		newCertGenerator := generator.NewCertGeneratorHandlerFromSigner(generator.CSRValidate, s)
		http.Handle("/api/v1/cfssl/newcert", newCertGenerator)
	}

	log.Info("Setting up bundler endpoint")
	bundleHandler, err := bundle.NewHandler(c.CABundleFile, c.IntBundleFile)
	if err != nil {
		log.Warningf("endpoint '/api/v1/cfssl/bundle' is disabled: %v", err)
	} else {
		http.Handle("/api/v1/cfssl/bundle", bundleHandler)
	}

	log.Info("Setting up CSR endpoint")
	generatorHandler, err := generator.NewHandler(generator.CSRValidate)
	if err != nil {
		log.Errorf("Failed to set up CSR endpoint: %v", err)
		return err
	}
	http.Handle("/api/v1/cfssl/newkey", generatorHandler)

	log.Info("Setting up initial CA endpoint")
	http.Handle("/api/v1/cfssl/init_ca", initca.NewHandler())

	log.Info("Setting up scan endpoint")
	http.Handle("/api/v1/cfssl/scan", scan.NewHandler())

	log.Info("Setting up scaninfo endpoint")
	http.Handle("/api/v1/cfssl/scaninfo", scan.NewInfoHandler())

	log.Info("Handler set up complete.")
	return nil
}

// serverMain is the command line entry point to the API server. It sets up a
// new HTTP server to handle sign, bundle, and validate requests.
func serverMain(args []string, c cli.Config) error {
	// serve doesn't support arguments.
	if len(args) > 0 {
		return errors.New("argument is provided but not defined; please refer to the usage by flag -h")
	}

	bundler.IntermediateStash = c.IntDir
	err := ubiquity.LoadPlatforms(c.Metadata)
	if err != nil {
		log.Error(err)
	}

	err = registerHandlers(c)
	if err != nil {
		return err
	}

	addr := fmt.Sprintf("%s:%d", c.Address, c.Port)
	log.Info("Now listening on ", addr)
	return http.ListenAndServe(addr, nil)
}

// CLIServer assembles the definition of Command 'serve'
var Command = &cli.Command{UsageText: serverUsageText, Flags: serverFlags, Main: serverMain}
