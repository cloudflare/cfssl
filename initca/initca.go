// initca contains code to initialise a certificate authority,
// generating a new root key and certificate.
package initca

import (
	"errors"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
)

// validator contains the default validation logic for certificate
// requests to the API server. This follows the Baseline Requirements
// for the Issuance and Management of Publicly-Trusted Certificates,
// v.1.1.6, from the CA/Browser Forum
// (https://cabforum.org). Specifically, section 10.2.3 ("Information
// Requirements"), states:
//
// "Applicant information MUST include, but not be limited to, at least one
// Fully-Qualified Domain Name or IP address to be included in the Certificate’s
// SubjectAltName extension."
func validator(req *csr.CertificateRequest) error {
	if len(req.Hosts) == 0 {
		return cferr.New(cferr.PolicyError, cferr.InvalidRequest, errors.New("missing hosts field"))
	}
	return nil
}

// New creates a new root certificate from the certificate request.
func New(req *csr.CertificateRequest) (cert, key []byte, err error) {
	log.Infof("creating root certificate from CSR")
	g := &csr.Generator{validator}
	csr, key, err := g.ProcessRequest(req)
	if err != nil {
		log.Errorf("failed to process request: %v", err)
		key = nil
		return
	}

	priv, err := helpers.ParsePrivateKeyPEM(key)
	if err != nil {
		log.Errorf("failed to parse private key: %v", err)
		return
	}

	s := signer.NewStandardSigner(priv, nil, signer.DefaultSigAlgo(priv))
	s.SetPolicy(CAPolicy)

	cert, err = s.Sign("", csr, "")
	return

}

// CAPolicy contains the CA issuing policy as default policy.
var CAPolicy = &config.Signing{
	Default: &config.SigningProfile{
		Usage:        []string{"cert sign", "crl sign"},
		ExpiryString: "43800h",
		Expiry:       5 * helpers.OneYear,
		CA:           true,
	},
}
