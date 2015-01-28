package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/selfsign"
)

var selfSignUsageText = `cfssl selfsign -- generate a new self-signed key and signed certificate

Usage of gencert:
        cfssl selfsign HOSTNAME CSRJSON

WARNING: this should ONLY be used for testing. This should never be
used in production.

WARNING: self-signed certificates are insecure; they do not provide
the authentication required for secure systems. Use these at your own
risk.

Arguments:
        HOSTNAME:   Hostname for the cert
        CSRJSON:    JSON file containing the request, use '-' for reading JSON from stdin

Flags:
`

var selfSignFlags = []string{"config"}

func selfSignMain(args []string) (err error) {
	if Config.hostname == "" && !Config.isCA {
		Config.hostname, args, err = popFirstArgument(args)
		if err != nil {
			return
		}
	}

	csrFile, args, err := popFirstArgument(args)
	if err != nil {
		return
	}

	csrFileBytes, err := readStdin(csrFile)
	if err != nil {
		return
	}

	var req csr.CertificateRequest
	err = json.Unmarshal(csrFileBytes, &req)
	if err != nil {
		return
	}

	var key, csrPEM []byte
	g := &csr.Generator{Validator: validator}
	csrPEM, key, err = g.ProcessRequest(&req)
	if err != nil {
		key = nil
		return
	}

	priv, err := helpers.ParsePrivateKeyPEM(key)
	if err != nil {
		key = nil
		return
	}

	var profile *config.SigningProfile

	// If there is a config, use its signing policy. Otherwise, leave policy == nil
	// and NewSigner will use DefaultConfig().
	if Config.cfg != nil {
		if Config.profile != "" && Config.cfg.Signing.Profiles != nil {
			profile = Config.cfg.Signing.Profiles[Config.profile]
		}
	}

	if profile == nil {
		profile = config.DefaultConfig()
		profile.Expiry = 2190 * time.Hour
	}

	cert, err := selfsign.Sign(priv, csrPEM, profile)
	if err != nil {
		key = nil
		priv = nil
		return
	}

	fmt.Fprintf(os.Stderr, `*** WARNING ***

Self-signed certificates are dangerous. Use this self-signed
certificate at your own risk.

It is strongly recommended that these certificates NOT be used
in production.

*** WARNING ***

`)
	printCert(key, csrPEM, cert)
	return
}

var CLISelfSign = &Command{selfSignUsageText, selfSignFlags, selfSignMain}
