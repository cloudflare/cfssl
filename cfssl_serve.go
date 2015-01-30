package main

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/bundler"
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
func registerHandlers() error {
	log.Info("Setting up info endpoint")
	infoHandler, err := api.NewInfoHandlerFromPEM([]string{Config.caFile})
	if err != nil {
		log.Warningf("endpoint '/api/v1/cfssl/info' is disabled: %v", err)
	} else {
		http.Handle("/api/v1/cfssl/info", infoHandler)
	}

	log.Info("Setting up signer endpoint")

	// Update the signing policy is updated to include flags from the configuration.
	// The remotes are set here.
	policy, err := signingPolicyFromConfig()
	if err != nil {
		return err
	}

	// Note: a nil policy can be sent in here and a default one will be created
	// but we don't do that because we need to create one to hold the remote address
	signHandler, err := api.NewSignHandler(Config.caFile, Config.caKeyFile, policy)
	if err != nil {
		log.Warningf("endpoint '/api/v1/cfssl/sign' is disabled: %v", err)
	} else {
		http.Handle("/api/v1/cfssl/sign", signHandler)
	}

	log.Info("Setting up bundler endpoint")
	bundleHandler, err := api.NewBundleHandler(Config.caBundleFile, Config.intBundleFile)
	if err != nil {
		log.Warningf("endpoint '/api/v1/cfssl/bundle' is disabled: %v", err)
	} else {
		http.Handle("/api/v1/cfssl/bundle", bundleHandler)
	}

	log.Info("Setting up CSR endpoint")
	generatorHandler, err := api.NewGeneratorHandler(api.CSRValidate)
	if err != nil {
		log.Errorf("Failed to set up CSR endpoint: %v", err)
		return err
	}
	http.Handle("/api/v1/cfssl/newkey", generatorHandler)

	log.Info("Setting up new cert endpoint")
	newCertGenerator, err := api.NewCertGeneratorHandler(api.CSRValidate,
		Config.caFile, Config.caKeyFile, policy)
	if err != nil {
		log.Errorf("endpoint '/api/v1/cfssl/newcert' is disabled")
	} else {
		http.Handle("/api/v1/cfssl/newcert", newCertGenerator)
	}

	log.Info("Setting up initial CA endpoint")
	http.Handle("/api/v1/cfssl/init_ca", api.NewInitCAHandler())

	log.Info("Handler set up complete.")
	return nil
}

// serverMain is the command line entry point to the API server. It sets up a
// new HTTP server to handle sign, bundle, and validate requests.
func serverMain(args []string) error {
	// serve doesn't support arguments.
	if len(args) > 0 {
		return errors.New("argument is provided but not defined; please refer to the usage by flag -h")
	}

	bundler.IntermediateStash = Config.intDir
	ubiquity.LoadPlatforms(Config.metadata)

	err := registerHandlers()
	if err != nil {
		return err
	}

	addr := fmt.Sprintf("%s:%d", Config.address, Config.port)
	log.Info("Now listening on ", addr)
	return http.ListenAndServe(addr, nil)
}

// CLIServer assembles the definition of Command 'serve'
var CLIServer = &Command{serverUsageText, serverFlags, serverMain}
