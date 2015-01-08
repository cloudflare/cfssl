package main

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cloudflare/cfssl/api/client"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/initca"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
)

var gencertUsageText = `cfssl gencert -- generate a new key and signed certificate

Usage of gencert:
        cfssl gencert [-initca] CSRJSON
        cfssl gencert [-remote remote_server] HOSTNAME CSRJSON
        cfssl gencert [-ca cert] [-ca-key key] HOSTNAME CSRJSON

Arguments:
        HOSTNAME:   Hostname for the cert
        CSRJSON:    JSON file containing the request, use '-' for reading JSON from stdin

	HOSTNAME should not be included when initalising a new CA.
Flags:
`

var gencertFlags = []string{"initca", "remote", "ca", "ca-key", "f"}

func gencertMain(args []string) (err error) {
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

	if Config.isCA {
		var key, cert []byte
		cert, err = initca.NewFromPEM(&req, Config.caKeyFile)
		if err != nil {
			log.Errorf("%v\n", err)
			log.Infof("generating a new CA key and certificate from CSR")
			cert, key, err = initca.New(&req)
			if err != nil {
				return
			}

		}
		printCert(key, nil, cert)

	} else {
		if Config.remote != "" {
			return gencertRemotely(req)
		}

		if Config.caFile == "" {
			log.Error("cannot sign certificate without a CA certificate (provide one with -ca)")
			return
		}

		if Config.caKeyFile == "" {
			log.Error("cannot sign certificate without a CA key (provide one with -ca-key)")
			return
		}

		var policy *config.Signing
		// If there is a config, use its signing policy. Otherwise, leave policy == nil
		// and NewSigner will use DefaultConfig().
		if Config.cfg != nil {
			policy = Config.cfg.Signing
		}

		if req.CA != nil {
			err = errors.New("ca section only permitted in initca")
			return
		}

		var key, csrPEM []byte
		g := &csr.Generator{Validator: validator}
		csrPEM, key, err = g.ProcessRequest(&req)
		if err != nil {
			key = nil
			return
		}

		var sign signer.Signer
		sign, err = signer.NewSigner(Config.caFile, Config.caKeyFile, policy)
		if err != nil {
			return
		}

		var cert []byte
		cert, err = sign.Sign(Config.hostname, csrPEM, nil, Config.profile)
		if err != nil {
			return
		}

		printCert(key, csrPEM, cert)
	}
	return nil
}

func printCert(key, csrPEM, cert []byte) {
	out := map[string]string{
		"cert": string(cert),
	}

	if key != nil {
		out["key"] = string(key)
	}

	if csrPEM != nil {
		out["csr"] = string(csrPEM)
	}

	jsonOut, err := json.Marshal(out)
	if err != nil {
		return
	}
	fmt.Printf("%s\n", jsonOut)
}

func gencertRemotely(req csr.CertificateRequest) error {
	srv := client.NewServer(Config.remote)

	g := &csr.Generator{Validator: validator}
	csrPEM, key, err := g.ProcessRequest(&req)
	if err != nil {
		key = nil
		return err
	}

	var cert []byte
	cert, err = srv.Sign(Config.hostname, csrPEM, Config.profile, "")
	if err != nil {
		return err
	}

	printCert(key, csrPEM, cert)
	return nil
}

// CLIGenCert is a subcommand that generates a new certificate from a
// JSON CSR request file.
var CLIGenCert = &Command{gencertUsageText, gencertFlags, gencertMain}
