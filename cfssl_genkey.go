package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/cloudflare/cfssl/csr"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/initca"
)

var genkeyUsageText = `cfssl genkey -- generate a new key and CSR

Usage of genkey:
        cfssl genkey CSRJSON

Arguments:
        CSRJSON:    JSON file containing the request, use '-' for reading JSON from stdin

Flags:
`

var genkeyFlags = []string{"initca", "f"}

func genkeyMain(args []string) (err error) {
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
		cert, key, err = initca.New(&req)
		if err != nil {
			return
		}

		var out = struct {
			Key  string `json:"key"`
			Cert string `json:"cert"`
		}{string(key), string(cert)}

		var jsonOut []byte
		jsonOut, err = json.Marshal(out)
		if err != nil {
			return
		}
		fmt.Printf("%s\n", string(jsonOut))

	} else {
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

		var out = struct {
			Key string `json:"key"`
			CSR string `json:"csr"`
		}{string(key), string(csrPEM)}

		var jsonOut []byte
		jsonOut, err = json.Marshal(out)
		if err != nil {
			return
		}
		fmt.Printf("%s\n", string(jsonOut))
	}
	return nil
}

func validator(req *csr.CertificateRequest) error {
	if len(req.Hosts) == 0 {
		return cferr.New(cferr.PolicyError, cferr.InvalidRequest, errors.New("missing hosts field"))
	}
	return nil
}

// CLIGenKey is a subcommand for generating a new key and CSR from a
// JSON CSR request file.
var CLIGenKey = &Command{genkeyUsageText, genkeyFlags, genkeyMain}
