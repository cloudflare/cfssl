package info

import (
	"encoding/json"
	"fmt"

	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/api/client"
	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/errors"

	goerr "errors"
)

var infoUsageTxt = `cfssl info -- get info about a remote signer

Usage:

Get info about a remote signer:
cfssl info -remote remote_host [-label label] [-profile profile] [-label label] 

Flags:
`

var infoFlags = []string{"remote", "label", "profile", "config"}

func infoMain(args []string, c cli.Config) (err error) {
	if len(args) > 0 {
		return goerr.New("argument is provided but not defined; please refer to the usage by flag -h.")
	}

	if c.Remote == "" {
		return goerr.New("Remote is not given; please refer to the usage by flag -h.")
	}

	serv := client.NewServer(c.Remote)

	req := new(client.InfoReq)
	req.Label = c.Label
	req.Profile = c.Profile

	reqJSON, _ := json.Marshal(req)
	certPem, err := serv.Info(reqJSON)
	if err != nil {
		return err
	}
	resp := client.InfoResp{
		Certificate: string(certPem),
	}
	response := api.NewSuccessResponse(resp)
	respJSON, err := json.Marshal(response)
	if err != nil {
		return errors.NewBadRequest(err)
	}
	fmt.Print(string(respJSON))
	return nil
}

// Command defines the commmand-line procedure for info
var Command = &cli.Command{
	UsageText: infoUsageTxt,
	Flags:     infoFlags,
	Main:      infoMain,
}
