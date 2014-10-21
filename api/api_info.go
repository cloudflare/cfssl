package api

import (
	"crypto/x509"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/cloudflare/cfssl/bundler"
	"github.com/cloudflare/cfssl/helpers"
)

// InfoHandler is a type that contains the root certificates for the CA,
// and serves information on them for clients that need the certificates.
type InfoHandler struct {
	roots []*x509.Certificate
}

// NewInfoHandler creates a new handler to serve information on the
// CA's certificates.
func NewInfoHandler(roots []*x509.Certificate) http.Handler {
	return &HTTPHandler{
		Handler: &InfoHandler{
			roots: roots,
		},
		Method: "GET",
	}
}

// NewInfoHandlerFromPEM creates a new handler to serve information on the
// CA's certificates, taking a list of PEM-encoded certificates to use.
func NewInfoHandlerFromPEM(pemRoots []string) (http.Handler, error) {
	var roots []*x509.Certificate
	for i := range pemRoots {
		fileData, err := ioutil.ReadFile(pemRoots[i])
		if err != nil {
			return nil, err
		}

		cert, err := helpers.ParseCertificatePEM(fileData)
		if err != nil {
			return nil, err
		}
		roots = append(roots, cert)
	}

	return &HTTPHandler{
		Handler: &InfoHandler{
			roots: roots,
		},
		Method: "GET",
	}, nil
}

// Handle listens for incoming requests for CA information, and returns
// a list containing information on each root certificate.
func (h *InfoHandler) Handle(w http.ResponseWriter, r *http.Request) error {
	var bundles []bundler.Bundle

	for i := range h.roots {
		bundles = append(bundles, bundler.Bundle{
			Chain:     []*x509.Certificate{h.roots[i]},
			Cert:      h.roots[i],
			Issuer:    &h.roots[i].Issuer,
			Subject:   &h.roots[i].Subject,
			Expires:   &h.roots[i].NotAfter,
			Hostnames: h.roots[i].DNSNames,
			Status:    nil,
		})
	}

	response := NewSuccessResponse(bundles)
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	return enc.Encode(response)
}
