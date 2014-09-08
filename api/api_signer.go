package api

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
)

// A SignHandler accepts requests with a hostname and certficate
// parameter (which should be PEM-encoded) and returns a new signed
// certificate.
type SignHandler struct {
	signer signer.Signer
}

// NewSignHandler generates a new SignHandler using the certificate
// authority private key and certficate to sign certificates.
func NewSignHandler(caFile, cakeyFile string) (http.Handler, error) {
	var err error
	s := new(SignHandler)
	// TODO(kyle): add profile loading to API server
	if s.signer, err = signer.NewSigner(caFile, cakeyFile, nil); err != nil {
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

// SignRequest stores a signature request, which contains the hostname,
// the CSR, optional subject information, and the signature profile.
type SignRequest struct {
	Hostname string          `json:"hostname"`
	Request  string          `json:"certificate_request"`
	Subject  *signer.Subject `json:"subject,omitempty"`
	Profile  string          `json:"profile"`
}

// Handle responds to requests for the CA to sign the certificate request
// present in the "certificate_requeset" parameter for the host named
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

	var req SignRequest
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

	cert, err := h.signer.Sign(req.Hostname, []byte(req.Request), req.Subject, req.Profile)
	if err != nil {
		log.Warningf("failed to sign request: %v", err)
		return errors.NewBadRequest(err)
	}

	result := map[string]string{"certificate": string(cert)}
	log.Info("wrote response")
	return sendResponse(w, result)
}
