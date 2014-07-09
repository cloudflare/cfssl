package main

import (
	"fmt"

	"github.com/cloudflare/cfssl/bundler"
	"github.com/cloudflare/cfssl/ubiquity"
)

// Usage text of 'cfssl bundle'
var bundlerUsageText = `cfssl bundle -- create a certificate bundle that contains the client cert

Usage of bundle:
	- Bundle local certificate files
        cfssl bundle [-ca-bundle file] [-int-bundle file] [-key keyfile] [-flavor int] [-metadata file] CERT
	- Bundle certificate from remote server.
        cfssl bundle -domain domain_name [-ip ip_address] [-ca-bundle file] [-int-bundle file] [-metadata file]

Arguments:
	CERT:          Client certificate that contains the public key, possible followed by intermediates to form a partial chain.

Note:
	CERT can be specified as flag value. But flag value will take precedence, overwriting the argument.

Flags:
`

// flags used by 'cfssl bundle'
var bundlerFlags = []string{"cert", "key", "ca-bundle", "int-bundle", "flavor", "metadata", "domain", "ip", "f"}

// bundlerMain is the main CLI of bundler functionality.
// TODO(zi): Decide whether to drop the argument list and only use flags to specify all the inputs.
// There are debates on whether flag or arg is more appropriate for required parameters.
func bundlerMain(args []string) (err error) {

	// Grab cert file through args only if flag values for cert and domain are absent
	if Config.certFile == "" && Config.domain == "" {
		Config.certFile, args, err = popFirstArgument(args)
		if err != nil {
			return
		}
	}

	ubiquity.LoadPlatforms(Config.metadata)
	flavor := bundler.BundleFlavor(Config.flavor)
	// Initialize a bundler with CA bundle and intermediate bundle.
	b, err := bundler.NewBundler(Config.caBundleFile, Config.intBundleFile)
	if err != nil {
		return
	}

	var bundle *bundler.Bundle
	if Config.certFile != "" {
		// Bundle the client cert
		bundle, err = b.BundleFromFile(Config.certFile, Config.keyFile, flavor)
		if err != nil {
			return
		}
	} else if Config.domain != "" {
		bundle, err = b.BundleFromRemote(Config.domain, Config.ip)
		if err != nil {
			return
		}
	}
	marshaled, err := bundle.MarshalJSON()
	if err != nil {
		return
	}
	fmt.Printf("%s", marshaled)
	return
}

// CLIBundler assembles the definition of Command 'bundle'
var CLIBundler = &Command{bundlerUsageText, bundlerFlags, bundlerMain}
