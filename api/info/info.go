package info

import (
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"net/http"

	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/api/client"
	"github.com/cloudflare/cfssl/bundler"
	"github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
)

// InfoHandler is a type that contains the root certificates for the CA,
// and serves information on them for clients that need the certificates.
type InfoHandler struct {
	sign signer.Signer
}

// NewInfoHandler creates a new handler to serve information on the CA's
// certificates, taking a signer to use.
func NewInfoHandler(s signer.Signer) (http.Handler, error) {
	return &api.HTTPHandler{
		Handler: &InfoHandler{
			sign: s,
		},
		Method: "POST",
	}, nil
}

// Handle listens for incoming requests for CA information, and returns
// a list containing information on each root certificate.
func (h *InfoHandler) Handle(w http.ResponseWriter, r *http.Request) error {

	req := new(client.InfoReq)
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

	cert, err := h.sign.Certificate(req.Label, req.Profile)
	if err != nil {
		return err
	}
	resp := client.InfoResp{
		Certificate: bundler.PemBlockToString(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
	}

	response := api.NewSuccessResponse(resp)
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	return enc.Encode(response)
}
