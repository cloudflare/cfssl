package main

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/initca"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
)

var gencertUsageText = `cfssl gencert -- generate a new key and signed certificate

Usage of gencert:
        cfssl gencert -initca CSRJSON
        cfssl gencert -ca cert -ca-key key [-config config] [-profile -profile] HOSTNAME CSRJSON
        cfssl gencert -remote remote_host [-config config] [-profile profile] [-label label] HOSTNAME CSRJSON

Arguments:
        HOSTNAME:   Hostname for the cert
        CSRJSON:    JSON file containing the request, use '-' for reading JSON from stdin

	HOSTNAME should not be included when initalising a new CA.
Flags:
`

var gencertFlags = []string{"initca", "remote", "ca", "ca-key", "config", "profile", "label"}

func gencertMain(args []string) (err error) {
	if Config.hostname == "" && !Config.isCA {
		Config.hostname, args, err = popFirstArgument(args)
		if err != nil {
			return
		}
	}

	csrJSONFile, args, err := popFirstArgument(args)
	if err != nil {
		return
	}

	csrJSONFileBytes, err := readStdin(csrJSONFile)
	if err != nil {
		return
	}

	var req csr.CertificateRequest
	err = json.Unmarshal(csrJSONFileBytes, &req)
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
		if req.CA != nil {
			err = errors.New("ca section only permitted in initca")
			return
		}

		// Remote can be forced on the command line or in the config
		if Config.remote == "" && Config.cfg == nil {
			if Config.caFile == "" {
				log.Error("need a CA certificate (provide one with -ca)")
				return
			}

			if Config.caKeyFile == "" {
				log.Error("need a CA key (provide one with -ca-key)")
				return
			}
		}

		var key, csrBytes []byte
		g := &csr.Generator{Validator: validator}
		csrBytes, key, err = g.ProcessRequest(&req)
		if err != nil {
			key = nil
			return
		}

		policy, err := signingPolicyFromConfig()
		if err != nil {
			return err
		}

		root := signer.Root{
			CertFile:    Config.caFile,
			KeyFile:     Config.caKeyFile,
			ForceRemote: Config.remote == "",
		}
		sign, err := signer.NewSigner(root, policy)
		if err != nil {
			return err
		}

		var cert []byte
		req := signer.SignRequest{
			Hostname: Config.hostname,
			Request:  string(csrBytes),
			Subject:  nil,
			Profile:  Config.profile,
			Label:    Config.label,
		}

		cert, err = sign.Sign(req)
		if err != nil {
			return err
		}

		printCert(key, csrBytes, cert)
	}
	return nil
}

func printCert(key, csrBytes, cert []byte) {
	out := map[string]string{}
	if cert != nil {
		out["cert"] = string(cert)
	}

	if key != nil {
		out["key"] = string(key)
	}

	if csrBytes != nil {
		out["csr"] = string(csrBytes)
	}

	jsonOut, err := json.Marshal(out)
	if err != nil {
		return
	}
	fmt.Printf("%s\n", jsonOut)
}

// CLIGenCert is a subcommand that generates a new certificate from a
// JSON CSR request file.
var CLIGenCert = &Command{gencertUsageText, gencertFlags, gencertMain}
