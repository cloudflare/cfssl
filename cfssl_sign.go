package main

import (
	"encoding/json"
	"io/ioutil"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
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

func signingPolicyFromConfig() (*config.Signing, error) {
	// If there is a config, use its signing policy. Otherwise create a default policy.
	var policy *config.Signing
	if Config.cfg != nil {
		policy = Config.cfg.Signing
	} else {
		policy = &config.Signing{
			Profiles: map[string]*config.SigningProfile{},
			Default:  config.DefaultConfig(),
		}
	}

	// Make sure the policy reflects the new remote
	if Config.remote != "" {
		err := policy.OverrideRemotes(Config.remote)
		if err != nil {
			log.Infof("Invalid remote %v, reverting to configuration default", Config.remote)
			return nil, err
		}
	}
	return policy, nil
}

// signerMain is the main CLI of signer functionality.
// [TODO: zi] Decide whether to drop the argument list and only use flags to specify all the inputs.
func signerMain(args []string) (err error) {
	// Grab values through args only if corresponding flags are absent
	if Config.hostname == "" {
		Config.hostname, args, err = popFirstArgument(args)
		if err != nil {
			return
		}
	}
	if Config.csrFile == "" {
		Config.csrFile, args, err = popFirstArgument(args)
		if err != nil {
			return
		}
	}

	var subjectData *signer.Subject
	if len(args) > 0 {
		var subjectFile string
		subjectFile, args, err = popFirstArgument(args)
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

	csr, err := readStdin(Config.csrFile)
	if err != nil {
		return
	}

	// Remote can be forced on the command line or in the config
	if Config.remote == "" && Config.cfg == nil {
		if Config.caFile == "" {
			log.Error("need CA certificate (provide one with -ca)")
			return
		}

		if Config.caKeyFile == "" {
			log.Error("need CA key (provide one with -ca-key)")
			return
		}
	}

	policy, err := signingPolicyFromConfig()
	if err != nil {
		return
	}

	root := signer.Root{
		CertFile:    Config.caFile,
		KeyFile:     Config.caKeyFile,
		ForceRemote: Config.remote == "",
	}
	s, err := signer.NewSigner(root, policy)
	if err != nil {
		return
	}

	req := signer.SignRequest{
		Hostname: Config.hostname,
		Request:  string(csr),
		Subject:  subjectData,
		Profile:  Config.profile,
		Label:    Config.label,
	}
	cert, err := s.Sign(req)
	if err != nil {
		return
	}
	printCert(nil, csr, cert)
	return
}

// CLISigner assembles the definition of Command 'sign'
var CLISigner = &Command{signerUsageText, signerFlags, signerMain}
