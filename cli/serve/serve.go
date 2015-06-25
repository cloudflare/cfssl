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
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/ubiquity"
)

// Usage text of 'cfssl serve'
var serverUsageText = `cfssl serve -- set up a HTTP server handles CF SSL requests

Usage of serve:
        cfssl serve [-address address] [-ca cert] [-ca-bundle bundle] \
                    [-ca-key key] [-int-bundle bundle] [-int-dir dir] [-port port] \
                    [-metadata file] [-remote remote_host] [-config config] [-uselocal]

Flags:
`

// Flags used by 'cfssl serve'
var serverFlags = []string{"address", "port", "ca", "ca-key", "ca-bundle", "int-bundle", "int-dir", "metadata", "remote", "config", "uselocal"}

var (
	c cli.Config
	s signer.Signer
)

var errBadSigner = errors.New("signer not initialized")

var v1Endpoints = map[string]func() (http.Handler, error){
	"sign": func() (http.Handler, error) {
		if s == nil {
			return nil, errBadSigner
		}
		return apisign.NewHandlerFromSigner(s)
	},

	"authsign": func() (http.Handler, error) {
		if s == nil {
			return nil, errBadSigner
		}
		return apisign.NewAuthHandlerFromSigner(s)
	},

	"info": func() (http.Handler, error) {
		if s == nil {
			return nil, errBadSigner
		}
		return info.NewHandler(s)
	},

	"newcert": func() (http.Handler, error) {
		if s == nil {
			return nil, errBadSigner
		}
		return generator.NewCertGeneratorHandlerFromSigner(generator.CSRValidate, s), nil
	},

	"bundle": func() (http.Handler, error) {
		return bundle.NewHandler(c.CABundleFile, c.IntBundleFile)
	},

	"newkey": func() (http.Handler, error) {
		return generator.NewHandler(generator.CSRValidate)
	},

	"init_ca": func() (http.Handler, error) {
		return initca.NewHandler(), nil
	},

	"scan": func() (http.Handler, error) {
		return scan.NewHandler(), nil
	},

	"scaninfo": func() (http.Handler, error) {
		return scan.NewInfoHandler(), nil
	},

	"/": func() (http.Handler, error) {
		return http.FileServer(FS(c.UseLocal)), nil
	},
}

// registerHandlers instantiates various handlers and associate them to corresponding endpoints.
func registerHandlers() {
	for path, getHandler := range v1Endpoints {
		if path != "/" {
			path = fmt.Sprintf("/api/v1/cfssl/%s", path)
		}

		log.Infof("Setting up '%s' endpoint", path)

		if handler, err := getHandler(); err != nil {
			log.Warningf("endpoint '%s' is disabled: %v", path, err)
		} else {
			http.Handle(path, handler)
		}
	}

	log.Info("Handler set up complete.")
}

// serverMain is the command line entry point to the API server. It sets up a
// new HTTP server to handle sign, bundle, and validate requests.
func serverMain(args []string, c cli.Config) error {
	// serve doesn't support arguments.
	if len(args) > 0 {
		return errors.New("argument is provided but not defined; please refer to the usage by flag -h")
	}

	bundler.IntermediateStash = c.IntDir
	var err error

	if err = ubiquity.LoadPlatforms(c.Metadata); err != nil {
		log.Error(err)
	}

	log.Info("Initializing signer")
	if s, err = sign.SignerFromConfig(c); err != nil {
		log.Warningf("couldn't initialize signer: %v", err)
	}

	registerHandlers()

	addr := fmt.Sprintf("%s:%d", c.Address, c.Port)
	log.Info("Now listening on ", addr)
	return http.ListenAndServe(addr, nil)
}

// CLIServer assembles the definition of Command 'serve'
var Command = &cli.Command{UsageText: serverUsageText, Flags: serverFlags, Main: serverMain}
