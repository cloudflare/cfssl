// Package info implements the info command.
package info

import (
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/cloudflare/cfssl/api/client"
	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/cli/sign"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/helpers"

	goerr "errors"
)

var infoUsageTxt = `cfssl info -- get info about a remote signer

Usage:

Get info about a remote signer:
cfssl info -remote remote_host [-label label] [-profile profile] [-label label] 

Flags:
`

var infoFlags = []string{"remote", "label", "profile", "config"}

func getInfoFromRemote(c cli.Config) (resp *client.InfoResp, err error) {

	req := new(client.InfoReq)
	req.Label = c.Label
	req.Profile = c.Profile

	serv := client.NewServer(c.Remote)

	reqJSON, _ := json.Marshal(req)
	resp, err = serv.Info(reqJSON)
	if err != nil {
		return
	}

	_, err = helpers.ParseCertificatePEM([]byte(resp.Certificate))
	if err != nil {
		return
	}

	return
}

func getInfoFromConfig(c cli.Config) (resp *client.InfoResp, err error) {
	s, err := sign.SignerFromConfig(c)
	if err != nil {
		return
	}

	cert, err := s.Certificate(c.Label, c.Profile)
	if err != nil {
		return
	}

	blk := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	certPem := pem.EncodeToMemory(&blk)

	var profile *config.SigningProfile

	policy := s.Policy()

	if policy != nil && policy.Profiles != nil && c.Profile != "" {
		profile = policy.Profiles[c.Profile]
	}

	if profile == nil && policy != nil {
		profile = policy.Default
	}

	resp = &client.InfoResp{
		Certificate:  string(certPem),
		Usage:        profile.Usage,
		ExpiryString: profile.ExpiryString,
	}

	return
}

func infoMain(args []string, c cli.Config) (err error) {
	if len(args) > 0 {
		return goerr.New("argument is provided but not defined; please refer to the usage by flag -h.")
	}

	var resp *client.InfoResp

	if c.Remote != "" {
		resp, err = getInfoFromRemote(c)
		if err != nil {
			return
		}

	} else if c.CFG != nil {
		resp, err = getInfoFromConfig(c)
		if err != nil {
			return
		}
	} else {
		return goerr.New("Either -remote or -config must be given. Refer to cfssl info -h for usage.")
	}

	respJSON, err := json.Marshal(resp)
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
