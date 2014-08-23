package api

import (
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
	return HttpHandler{s, "POST"}, nil
}

// NewSignHandlerFromSigner generates a new SignHandler directly from
// an existing signer.
func NewSignHandlerFromSigner(signer signer.Signer) HttpHandler {
	return HttpHandler{
		&SignHandler{
			signer: signer,
		},
		"POST",
	}
}

// Handle responds to requests for the CA to sign the certificate
// present in the "cert" parameter for the host named in the "hostname"
// parameter. The certificate should be PEM-encoded.
func (h *SignHandler) Handle(w http.ResponseWriter, r *http.Request) error {
	log.Info("signature request received")
	blob, err := processRequestRequired(r, []string{"hostname", "certificate_request"})
	if err != nil {
		return err
	}

	certificate := []byte(blob["certificate_request"])
	cert, err := h.signer.Sign(blob["hostname"], certificate, blob["profile"])
	if err != nil {
		log.Warningf("failed to sign request: %v", err)
		return errors.NewBadRequest(err)
	}

	result := map[string]string{"certificate": string(cert)}
	log.Info("wrote response")
	return sendResponse(w, result)
}
