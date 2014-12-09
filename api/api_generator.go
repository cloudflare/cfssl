package api

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/cloudflare/cfssl/api/client"
	"github.com/cloudflare/cfssl/config"
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
	Key  string         `json:"private_key"`
	CSR  string         `json:"certificate_request"`
	Sums map[string]Sum `json:"sums"`
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

func computeSum(in []byte) (sum Sum, err error) {
	var data []byte
	p, _ := pem.Decode(in)
	if p == nil {
		err = errors.NewBadRequestString("not a CSR or certificate")
		return
	}

	switch p.Type {
	case "CERTIFICATE REQUEST":
		var req *x509.CertificateRequest
		req, err = x509.ParseCertificateRequest(p.Bytes)
		if err != nil {
			return
		}
		data = req.Raw
	case "CERTIFICATE":
		var cert *x509.Certificate
		cert, err = x509.ParseCertificate(p.Bytes)
		if err != nil {
			return
		}
		data = cert.Raw
	default:
		err = errors.NewBadRequestString("not a CSR or certificate")
		return
	}

	md5Sum := md5.Sum(data)
	sha1Sum := sha1.Sum(data)
	sum.MD5 = fmt.Sprintf("%X", md5Sum[:])
	sum.SHA1 = fmt.Sprintf("%X", sha1Sum[:])
	return
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

	sum, err := computeSum(csr)
	if err != nil {
		return errors.NewBadRequest(err)
	}

	// Both key and csr are returned PEM-encoded.
	response := NewSuccessResponse(&CertRequest{
		Key:  string(key),
		CSR:  string(csr),
		Sums: map[string]Sum{"certificate_request": sum},
	})
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
	server    *client.Server
	policy    *config.Signing
}

// NewCertGeneratorHandler builds a new handler for generating
// certificates directly from certificate requests; the validator covers
// the certificate request and the CA's key and certificate are used to
// sign the generated request. If remote is not an empty string, the
// handler will send signature requests to the CFSSL instance contained
// in remote.
func NewCertGeneratorHandler(validator Validator, caFile, caKeyFile, remote string, cfg *config.Signing) (http.Handler, error) {
	var err error
	log.Info("setting up new generator / signer")
	cg := new(CertGeneratorHandler)

	if cfg == nil {
		cfg = &config.Signing{
			Default:  config.DefaultConfig(),
			Profiles: nil,
		}
	}

	if cg.signer, err = signer.NewSigner(caFile, caKeyFile, cfg); err != nil {
		if remote == "" {
			return nil, err
		}
		log.Infof("remote cert generator activated")
		cg.signer = nil
	}

	cg.policy = cfg
	cg.generator = &csr.Generator{Validator: validator}
	if remote != "" {
		cg.server = client.NewServer(remote)
		if cg.server == nil {
			return nil, errors.New(errors.DialError, errors.None)
		}
	}

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
	Label    string                  `json:"label"`
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

	var certPEM []byte
	profile := cg.policy.Default
	if cg.policy.Profiles != nil {
		profile = cg.policy.Profiles[req.Profile]
	}

	if profile == nil {
		log.Critical("invalid profile ", req.Profile)
		return errors.NewBadRequestString("invalid profile")
	}

	if cg.server != nil {
		if profile.Provider != nil {
			authSign := authSign{
				CSR:     csr,
				Profile: profile,
				Server:  cg.server,
				Request: req,
			}
			certPEM, err = cg.handleAuthSign(w, &authSign)
		} else {
			certPEM, err = cg.server.Sign(req.Hostname, csr, req.Profile, req.Label)
		}
	} else if profile.Remote != nil {
		if profile.Provider != nil {
			authSign := authSign{
				CSR:     csr,
				Profile: profile,
				Server:  profile.Remote,
				Request: req,
			}
			certPEM, err = cg.handleAuthSign(w, &authSign)
		} else {
			certPEM, err = profile.Remote.Sign(req.Hostname, csr, req.Profile, req.Label)
		}
	} else {
		certPEM, err = cg.signer.Sign(req.Hostname, csr, nil, req.Profile)
	}

	if err != nil {
		log.Warningf("failed to sign request: %v", err)
		return err
	}

	reqSum, err := computeSum(csr)
	if err != nil {
		return errors.NewBadRequest(err)
	}

	certSum, err := computeSum(certPEM)
	if err != nil {
		return errors.NewBadRequest(err)
	}

	result := map[string]interface{}{
		"private_key":         string(key),
		"certificate_request": string(csr),
		"certificate":         string(certPEM),
		"sums": map[string]Sum{
			"certificate_request": reqSum,
			"certificate":         certSum,
		},
	}
	return sendResponse(w, result)
}

type authSign struct {
	CSR     []byte
	Profile *config.SigningProfile
	Server  *client.Server
	Request *genSignRequest
}

// handleAuthSign takes care of packaging the request and sending it
// off to the authenticated signing endpoint.
func (cg *CertGeneratorHandler) handleAuthSign(w http.ResponseWriter, authSign *authSign) ([]byte, error) {
	if authSign.CSR == nil || authSign.Profile == nil {
		return nil, errors.NewBadRequestString("invalid parameters to authsign")
	}

	if authSign.Server == nil {
		return nil, errors.NewBadRequestString("no remote server could be used")
	}

	request := SignRequest{
		Hostname: authSign.Request.Hostname,
		Request:  string(authSign.CSR),
		Profile:  authSign.Request.Profile,
	}

	jsonOut, err := json.Marshal(request)
	if err != nil {
		return nil, errors.NewBadRequest(err)
	}

	return authSign.Server.AuthSign(jsonOut, nil, request.Profile, authSign.Profile.Provider)
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
