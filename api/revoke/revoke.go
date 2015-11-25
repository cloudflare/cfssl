// Package revoke implements the HTTP handler for the revoke command
package revoke

import (
	"database/sql"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/ocsp"
)

// A Handler accepts requests with a serial number parameter
// and revokes
type Handler struct {
	db *sql.DB
}

// NewHandler returns a new http.Handler that handles a revoke request.
func NewHandler(db *sql.DB) http.Handler {
	return &api.HTTPHandler{
		Handler: &Handler{
			db: db,
		},
		Methods: []string{"POST"},
	}
}

// This type is meant to be unmarshalled from JSON
type jsonRevokeRequest struct {
	Serial string `json:"serial"`
	Reason string `json:"reason"`
}

// Handle responds to revocation requests. It attempts to revoke
// a certificate with a given serial number
func (h *Handler) Handle(w http.ResponseWriter, r *http.Request) error {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	r.Body.Close()

	// Default the status to good so it matches the cli
	var req jsonRevokeRequest
	err = json.Unmarshal(body, &req)
	if err != nil {
		return errors.NewBadRequestString("Unable to parse revocation request")
	}

	if len(req.Serial) == 0 {
		return errors.NewBadRequestString("serial number is required but not provided")
	}

	if req.Reason == "" {
		req.Reason = "0"
	}

	reasonCode, present := ocsp.RevocationReasonCodes[strings.ToLower(req.Reason)]
	if !present {
		reasonCode, err = strconv.Atoi(req.Reason)
		if err != nil {
			return err
		}
	}

	err = certdb.RevokeCertificate(h.db, req.Serial, reasonCode)
	result := map[string]string{}
	return api.SendResponse(w, result)
}
