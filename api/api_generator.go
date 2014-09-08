package api

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/cloudflare/cfssl/api/client"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
)

// Validator is a type of function that contains the logic for validating
// a certificate request.
type Validator func(*csr.CertificateRequest) error

// A CertRequest stores a PEM-encoded private key and corresponding
// CSR; this is returned from the CSR generation endpoint.
type CertRequest struct {
	Key string `json:"key"`
	CSR string `json:"csr"`
}

// A GeneratorHandler accepts JSON-encoded certificate requests and
// returns a new private key and certificate request.
type GeneratorHandler struct {
	generator *csr.Generator
}

// NewGeneratorHandler builds a new GeneratorHandler from the
// validation function provided.
func NewGeneratorHandler(validator Validator) (http.Handler, error) {
	log.Info("setting up key / CSR generator")
	return HTTPHandler{&GeneratorHandler{
		generator: &csr.Generator{Validator: validator},
	}, "POST"}, nil
}

// Handle responds to requests for the CA to generate a new private
// key and certificate request on behalf of the client. The format for
// these requests is documented in the API documentation.
func (g *GeneratorHandler) Handle(w http.ResponseWriter, r *http.Request) error {
	log.Info("request for CSR")
	req := new(csr.CertificateRequest)
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Warningf("failed to read request body: %v", err)
		return errors.NewBadRequest(err)
	}

	err = json.Unmarshal(body, req)
	if err != nil {
		log.Warningf("failed to unmarshal request: %v", err)
		return errors.NewBadRequest(err)
	}

	if req.CA != nil {
		log.Warningf("request received with CA section")
		return errors.NewBadRequestString("ca section only permitted in initca")
	}

	csr, key, err := g.generator.ProcessRequest(req)
	if err != nil {
		log.Warningf("failed to process CSR: %v", err)
		// The validator returns a *cfssl/errors.HttpError
		return err
	}

	// Both key and csr are returned PEM-encoded.
	response := newSuccessResponse(&CertRequest{string(key), string(csr)})
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	err = enc.Encode(response)
	return err
}

// A CertGeneratorHandler accepts JSON-encoded certificate requests
// and returns a new private key and signed certificate; it handles
// sending the CSR to the server.
type CertGeneratorHandler struct {
	generator *csr.Generator
	signer    signer.Signer
}

// NewCertGeneratorHandler builds a new handler for generating
// certificates directly from certificate requests; the validator covers
// the certificate request and the CA's key and certificate are used to
// sign the generated request.
func NewCertGeneratorHandler(validator Validator, caFile, caKeyFile string) (http.Handler, error) {
	var err error
	log.Info("setting up new generator / signer")
	cg := new(CertGeneratorHandler)
	if cg.signer, err = signer.NewSigner(caFile, caKeyFile, nil); err != nil {
		return nil, err
	}
	cg.generator = &csr.Generator{Validator: validator}

	return HTTPHandler{cg, "POST"}, nil
}

// NewCertGeneratorHandlerFromSigner returns a handler directly from
// the signer and validation function.
func NewCertGeneratorHandlerFromSigner(validator Validator, signer signer.Signer) http.Handler {
	return HTTPHandler{
		Handler: &CertGeneratorHandler{
			generator: &csr.Generator{Validator: validator},
			signer:    signer,
		},
		Method: "POST",
	}
}

type genSignRequest struct {
	Hostname string                  `json:"hostname"`
	Request  *csr.CertificateRequest `json:"request"`
	Profile  string                  `json:"profile"`
}

// Handle responds to requests for the CA to generate a new private
// key and certificate on behalf of the client. The format for these
// requests is documented in the API documentation.
func (cg *CertGeneratorHandler) Handle(w http.ResponseWriter, r *http.Request) error {
	log.Info("request for CSR")

	req := new(genSignRequest)
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Warningf("failed to read request body: %v", err)
		return errors.NewBadRequest(err)
	}

	err = json.Unmarshal(body, req)
	if err != nil {
		log.Warningf("failed to unmarshal request: %v", err)
		return errors.NewBadRequest(err)
	}

	if req.Request == nil {
		log.Warning("empty request received")
		return errors.NewBadRequestString("missing request section")
	}

	if req.Request.CA != nil {
		log.Warningf("request received with CA section")
		return errors.NewBadRequestString("ca section only permitted in initca")
	}

	csr, key, err := cg.generator.ProcessRequest(req.Request)
	if err != nil {
		log.Warningf("failed to process CSR: %v", err)
		// The validator returns a *cfssl/errors.HttpError
		return err
	}

	certPEM, err := cg.signer.Sign(req.Hostname, csr, nil, req.Profile)
	if err != nil {
		log.Warningf("failed to sign certificate: %v", err)
		return errors.NewBadRequest(err)
	}

	result := map[string]string{
		"private_key": string(key),
		"certificate": string(certPEM),
	}
	return sendResponse(w, result)
}

// A RemoteCertGeneratorHandler accepts CSR requests and submits the
// certificate to a remote CFSSL instance.
type RemoteCertGeneratorHandler struct {
	generator *csr.Generator
	remote    *client.Server
}

// NewRemoteCertGenerator builds a remote certificate generator from a
// CSR validator and the server string.
func NewRemoteCertGenerator(validator Validator, remote string) (http.Handler, error) {
	log.Info("setting up a new remote certificate generator")
	cg := new(RemoteCertGeneratorHandler)
	if cg.remote = client.NewServer(remote); cg.remote == nil {
		log.Errorf("invalid address for remote server")
		return nil, errors.New(errors.DialError, errors.Unknown, nil)
	}

	cg.generator = &csr.Generator{Validator: validator}
	return HTTPHandler{cg, "POST"}, nil
}

// Handle listens for certificate signature requests and submits the
// generated CSR to a remote CFSSL instance to sign the CSR and build
// a certificate.
func (rcg *RemoteCertGeneratorHandler) Handle(w http.ResponseWriter, r *http.Request) error {
	req := new(genSignRequest)
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Warningf("failed to read request body: %v", err)
		return errors.NewBadRequest(err)
	}

	err = json.Unmarshal(body, req)
	if err != nil {
		log.Warningf("failed to unmarshal request: %v", err)
		return errors.NewBadRequest(err)
	} else if req == nil || req.Request == nil {
		log.Warningf("invalid request received")
		return errors.NewBadRequestString("invalid request")
	}

	if req.Request == nil {
		log.Warning("empty request received")
		return errors.NewBadRequestString("missing request section")
	}

	if req.Request.CA != nil {
		log.Warningf("request received with CA section")
		return errors.NewBadRequestString("ca section only permitted in initca")
	}

	csrPEM, key, err := rcg.generator.ProcessRequest(req.Request)
	if err != nil {
		log.Warningf("failed to process CSR: %v", err)
		// The validator returns a *cfssl/errors.HttpError
		return err
	}

	certPEM, err := rcg.remote.Sign(req.Hostname, csrPEM, req.Profile)
	if err != nil {
		log.Warningf("failed to send CSR to remote signer: %v", err)
		return err
	}

	result := map[string]string{
		"private_key": string(key),
		"certificate": string(certPEM),
	}
	return sendResponse(w, result)
}

// CSRValidate contains the default validation logic for certificate requests to
// the API server. This follows the Baseline Requirements for the Issuance and
// Management of Publicly-Trusted Certificates, v.1.1.6, from the CA/Browser
// Forum (https://cabforum.org). Specifically, section 10.2.3 ("Information
// Requirements"), states:
//
// "Applicant information MUST include, but not be limited to, at least one
// Fully-Qualified Domain Name or IP address to be included in the Certificate’s
// SubjectAltName extension."
func CSRValidate(req *csr.CertificateRequest) error {
	if len(req.Hosts) == 0 {
		log.Warning("request for CSR is missing the host parameter")
		return errors.NewBadRequestMissingParameter("hosts")
	}
	return nil
}
