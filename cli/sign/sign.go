package sign

import (
	"encoding/json"
	"io/ioutil"

	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/universal"
)

// Usage text of 'cfssl sign'
var signerUsageText = `cfssl sign -- signs a client cert with a host name by a given CA and CA key

Usage of sign:
        cfssl sign -ca cert -ca-key key [-config config] [-profile profile] HOSTNAME CSR [SUBJECT]
        cfssl sign -remote remote_host [-config config] [-profile profile] [-label label] HOSTNAME CSR [SUBJECT]

Arguments:
        HOSTNAME:   Hostname for the cert
        CSR:        PEM file for certificate request, use '-' for reading PEM from stdin.

Note: HOSTNAME and CSR can also be supplied via flag values; flag values will take precedence over the argument.

SUBJECT is an optional file containing subject information to use for the certificate instead of the subject information in the CSR.

Flags:
`

// Flags of 'cfssl sign'
var signerFlags = []string{"hostname", "csr", "ca", "ca-key", "config", "profile", "label", "remote"}

// SignerFromConfig takes the Config and creates the appropriate
// signer.Signer object
func SignerFromConfig(c cli.Config) (signer.Signer, error) {
	// If there is a config, use its signing policy. Otherwise create a default policy.
	var policy *config.Signing
	if c.CFG != nil {
		policy = c.CFG.Signing
	} else {
		policy = &config.Signing{
			Profiles: map[string]*config.SigningProfile{},
			Default:  config.DefaultConfig(),
		}
	}

	// Make sure the policy reflects the new remote
	if c.Remote != "" {
		err := policy.OverrideRemotes(c.Remote)
		if err != nil {
			log.Infof("Invalid remote %v, reverting to configuration default", c.Remote)
			return nil, err
		}
	}

	root := universal.Root{
		CertFile:    c.CAFile,
		KeyFile:     c.CAKeyFile,
		ForceRemote: c.Remote != "",
	}

	s, err := universal.NewSigner(root, policy)
	if err != nil {
		return nil, err
	}

	return s, nil
}

// signerMain is the main CLI of signer functionality.
// [TODO: zi] Decide whether to drop the argument list and only use flags to specify all the inputs.
func signerMain(args []string, c cli.Config) (err error) {
	// Grab values through args only if corresponding flags are absent
	if c.Hostname == "" {
		c.Hostname, args, err = cli.PopFirstArgument(args)
		if err != nil {
			return
		}
	}
	if c.CSRFile == "" {
		c.CSRFile, args, err = cli.PopFirstArgument(args)
		if err != nil {
			return
		}
	}

	var subjectData *signer.Subject
	if len(args) > 0 {
		var subjectFile string
		subjectFile, args, err = cli.PopFirstArgument(args)
		if err != nil {
			return
		}

		var subjectJSON []byte
		subjectJSON, err = ioutil.ReadFile(subjectFile)
		if err != nil {
			return
		}

		subjectData = new(signer.Subject)
		err = json.Unmarshal(subjectJSON, subjectData)
		if err != nil {
			return
		}
	}

	csr, err := cli.ReadStdin(c.CSRFile)
	if err != nil {
		return
	}

	// Remote can be forced on the command line or in the config
	if c.Remote == "" && c.CFG == nil {
		if c.CAFile == "" {
			log.Error("need CA certificate (provide one with -ca)")
			return
		}

		if c.CAKeyFile == "" {
			log.Error("need CA key (provide one with -ca-key)")
			return
		}
	}

	s, err := SignerFromConfig(c)
	if err != nil {
		return
	}

	req := signer.SignRequest{
		Hostname: c.Hostname,
		Request:  string(csr),
		Subject:  subjectData,
		Profile:  c.Profile,
		Label:    c.Label,
	}
	cert, err := s.Sign(req)
	if err != nil {
		return
	}
	cli.PrintCert(nil, csr, cert)
	return
}

// CLISigner assembles the definition of Command 'sign'
var Command = &cli.Command{UsageText: signerUsageText, Flags: signerFlags, Main: signerMain}
