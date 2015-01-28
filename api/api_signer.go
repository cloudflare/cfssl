package api

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/cloudflare/cfssl/auth"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
)

// A SignHandler accepts requests with a hostname and certficate
// parameter (which should be PEM-encoded) and returns a new signed
// certificate. It includes upstream servers indexed by their
// profile name.
type SignHandler struct {
	signer signer.Signer
}

// NewSignHandler generates a new SignHandler using the certificate
// authority private key and certficate to sign certificates. If remote
// is not an empty string, the handler will send signature requests to
// the CFSSL instance contained in remote by default.
func NewSignHandler(caFile, cakeyFile string, policy *config.Signing) (http.Handler, error) {
	var err error
	s := new(SignHandler)

	if s.signer, err = signer.NewSigner(signer.Root{CertFile: caFile, KeyFile: cakeyFile}, policy); err != nil {
		log.Errorf("setting up signer failed: %v", err)
		return nil, err
	}

	return HTTPHandler{s, "POST"}, nil
}

// NewSignHandlerFromSigner generates a new SignHandler directly from
// an existing signer.
func NewSignHandlerFromSigner(signer signer.Signer) HTTPHandler {
	return HTTPHandler{
		&SignHandler{
			signer: signer,
		},
		"POST",
	}
}

// Handle responds to requests for the CA to sign the certificate request
// present in the "certificate_request" parameter for the host named
// in the "hostname" parameter. The certificate should be PEM-encoded. If
// provided, subject information from the "subject" parameter will be used
// in place of the subject information from the CSR.
func (h *SignHandler) Handle(w http.ResponseWriter, r *http.Request) error {
	log.Info("signature request received")

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	r.Body.Close()

	var req signer.SignRequest
	err = json.Unmarshal(body, &req)
	if err != nil {
		return err
	}

	if req.Hostname == "" {
		return errors.NewBadRequestString("missing hostname parameter")
	}

	if req.Request == "" {
		return errors.NewBadRequestString("missing certificate_request parameter")
	}

	var cert []byte
	var profile *config.SigningProfile

	policy := h.signer.Policy()
	if policy != nil && policy.Profiles != nil && req.Profile != "" {
		profile = policy.Profiles[req.Profile]
	}

	if profile == nil && policy != nil {
		profile = policy.Default
	}

	cert, err = h.signer.Sign(req)
	if err != nil {
		log.Warningf("failed to sign request: %v", err)
		return err
	}

	result := map[string]string{"certificate": string(cert)}
	log.Info("wrote response")
	return sendResponse(w, result)
}

// An AuthSignHandler verifies and signs incoming signature requests.
type AuthSignHandler struct {
	signer signer.Signer
}

// NewAuthSignHandler creates a new AuthSignHandler from the signer
// that is passed in.
func NewAuthSignHandler(signer signer.Signer) (http.Handler, error) {
	policy := signer.Policy()
	if policy == nil {
		return nil, errors.New(errors.PolicyError, errors.InvalidPolicy)
	}

	if policy.Default == nil && policy.Profiles == nil {
		return nil, errors.New(errors.PolicyError, errors.InvalidPolicy)
	}

	// If not every profile has an auth provider, the
	// configuration for this endpoint is invalid. We start the
	// check with the initial value that indicates the presence of
	// a default authentication provider.
	var hasProviders = (policy.Default.Provider != nil)
	for _, profile := range policy.Profiles {
		// A single profile without a provider will cause hasProviders to be false.
		hasProviders = hasProviders && (profile.Provider != nil)
	}

	if !hasProviders {
		return nil, errors.New(errors.PolicyError, errors.InvalidPolicy)
	}

	return &HTTPHandler{
		&AuthSignHandler{
			signer: signer,
		},
		"POST",
	}, nil
}

// Handle receives the incoming request, validates it, and processes it.
func (h *AuthSignHandler) Handle(w http.ResponseWriter, r *http.Request) error {
	log.Info("signature request received")

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Errorf("failed to read response body: %v", err)
		return err
	}
	r.Body.Close()

	var aReq auth.AuthenticatedRequest
	err = json.Unmarshal(body, &aReq)
	if err != nil {
		log.Errorf("failed to unmarshal authenticated request: %v", err)
		return errors.NewBadRequest(err)
	}

	var req signer.SignRequest
	err = json.Unmarshal(aReq.Request, &req)
	if err != nil {
		log.Errorf("failed to unmarshal request from authenticated request: %v", err)
		return errors.NewBadRequest(err)
	}

	// Sanity checks to ensure that we have a valid policy. This
	// should have been checked in NewAuthSignHandler.
	policy := h.signer.Policy()
	if policy == nil {
		log.Critical("signer was initialised without a signing policy")
		return errors.NewBadRequestString("invalid policy")
	}
	profile := policy.Default

	if policy.Profiles != nil {
		profile = policy.Profiles[req.Profile]
	}

	if profile == nil {
		log.Critical("signer was initialised without any valid profiles")
		return errors.NewBadRequestString("invalid profile")
	}

	if profile.Provider == nil {
		log.Error("profile has no authentication provider")
		return errors.NewBadRequestString("no authentication provider")
	}

	if !profile.Provider.Verify(&aReq) {
		log.Warning("received authenticated request with invalid token")
		return errors.NewBadRequestString("invalid token")
	}

	if req.Hostname == "" {
		return errors.NewBadRequestString("missing hostname parameter")
	}

	if req.Request == "" {
		return errors.NewBadRequestString("missing certificate_request parameter")
	}

	cert, err := h.signer.Sign(req)
	if err != nil {
		log.Errorf("signature failed: %v", err)
		return err
	}

	result := map[string]string{"certificate": string(cert)}
	log.Info("wrote response")
	return sendResponse(w, result)
}
