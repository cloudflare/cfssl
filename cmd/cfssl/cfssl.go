/*
cfssl is the command line tool to issue/sign/bundle client certificate. It's
also a tool to start a HTTP server to handle web requests for signing, bundling
and verification.

Usage:
	cfssl command [-flags] arguments

	The commands are

	bundle	 create a certificate bundle
	sign	 signs a certificate signing request (CSR)
	serve	 starts a HTTP server handling sign and bundle requests
	version	 prints the current cfssl version
	genkey   generates a key and an associated CSR
	gencert  generates a key and a signed certificate
	selfsign generates a self-signed certificate

Use "cfssl [command] -help" to find out more about a command.
*/
package main

import (
	"flag"

	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/cli/bundle"
	"github.com/cloudflare/cfssl/cli/gencert"
	"github.com/cloudflare/cfssl/cli/genkey"
	"github.com/cloudflare/cfssl/cli/selfsign"
	"github.com/cloudflare/cfssl/cli/serve"
	"github.com/cloudflare/cfssl/cli/sign"
	"github.com/cloudflare/cfssl/cli/version"
	"github.com/cloudflare/cfssl/log"
)

// main defines the cfssl usage and registers all defined commands and flags.
func main() {
	// Add command names to cfssl usage
	flag.IntVar(&log.Level, "loglevel", log.LevelInfo, "Log level")
	// Register commands.
	cmds := map[string]*cli.Command{
		"bundle":   bundle.Command,
		"sign":     sign.Command,
		"serve":    serve.Command,
		"version":  version.Command,
		"genkey":   genkey.Command,
		"gencert":  gencert.Command,
		"selfsign": selfsign.Command,
	}
	// Register all command flags.
	c := cli.RegisterFlags()
	cli.Start(cmds, c)
}
