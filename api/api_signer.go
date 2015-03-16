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
	"github.com/cloudflare/cfssl/signer/universal"
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
func NewSignHandler(caFile, caKeyFile string, policy *config.Signing) (http.Handler, error) {
	root := universal.Root{
		Config: map[string]string{
			"cert-file": caFile,
			"key-file":  caKeyFile,
		},
	}
	s, err := universal.NewSigner(root, policy)
	if err != nil {
		log.Errorf("setting up signer failed: %v", err)
		return nil, err
	}

	return NewSignHandlerFromSigner(s)
}

// NewSignHandlerFromSigner generates a new SignHandler directly from
// an existing signer.
func NewSignHandlerFromSigner(signer signer.Signer) (h HTTPHandler, err error) {
	policy := signer.Policy()
	if policy == nil {
		err = errors.New(errors.PolicyError, errors.InvalidPolicy)
		return
	}

	// Sign will only respond for profiles that have no auth provider.
	// So if all of the profiles require authentication, we return an error.
	haveUnauth := (policy.Default.Provider == nil)
	for _, profile := range policy.Profiles {
		if haveUnauth {
			break
		}
		haveUnauth = (profile.Provider == nil)
	}

	if !haveUnauth {
		err = errors.New(errors.PolicyError, errors.InvalidPolicy)
		return
	}

	return HTTPHandler{
		&SignHandler{
			signer: signer,
		},
		"POST",
	}, nil
}

// This type is meant to be unmarshalled from JSON so that there can be a
// hostname field in the API
// TODO: Change the API such that the normal struct can be used.
type jsonSignRequest struct {
	Hosts    []string        `json:"hosts"`
	Hostname string          `json:"hostname"`
	Request  string          `json:"certificate_request"`
	Subject  *signer.Subject `json:"subject,omitempty"`
	Profile  string          `json:"profile"`
	Label    string          `json:"label"`
}

func jsonReqToTrue(js jsonSignRequest) signer.SignRequest {
	sub := new(signer.Subject)
	if js.Subject == nil {
		sub = nil
	} else {
		// make a copy
		*sub = *js.Subject
	}

	var hosts []string
	if len(js.Hosts) > 0 {
		hosts = js.Hosts
	} else {
		hosts = signer.SplitHosts(js.Hostname)
	}

	return signer.SignRequest{
		Hosts:   hosts,
		Subject: sub,
		Request: js.Request,
		Profile: js.Profile,
		Label:   js.Label,
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

	var req jsonSignRequest
	err = json.Unmarshal(body, &req)
	if err != nil {
		return err
	}

	if req.Hostname == "" && len(req.Hosts) == 0 {
		return errors.NewBadRequestString("missing hostnames")
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

	if profile.Provider != nil {
		log.Error("profile requires authentication")
		return errors.NewBadRequestString("authentication required")
	}

	cert, err = h.signer.Sign(jsonReqToTrue(req))
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

	// AuthSign will not respond for profiles that have no auth provider.
	// So if there are no profiles with auth providers in this policy,
	// we return an error.
	haveAuth := (policy.Default.Provider != nil)
	for _, profile := range policy.Profiles {
		if haveAuth {
			break
		}
		haveAuth = (profile.Provider != nil)
	}

	if !haveAuth {
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

	var req jsonSignRequest
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

	if req.Hostname == "" && len(req.Hosts) == 0 {
		log.Warningf("JSON Request: %v", string(aReq.Request))
		log.Warningf("Request: %+v", req)
		return errors.NewBadRequestString("missing hostnames")
	}

	if req.Request == "" {
		return errors.NewBadRequestString("missing certificate_request parameter")
	}

	cert, err := h.signer.Sign(jsonReqToTrue(req))
	if err != nil {
		log.Errorf("signature failed: %v", err)
		return err
	}

	result := map[string]string{"certificate": string(cert)}
	log.Info("wrote response")
	return sendResponse(w, result)
}
