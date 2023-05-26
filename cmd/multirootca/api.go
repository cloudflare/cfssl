package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"

	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/auth"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/whitelist"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// A SignatureResponse contains only a certificate, as there is no other
// useful data for the CA to return at this time.
type SignatureResponse struct {
	Certificate string `json:"certificate"`
}

type filter func(string, *signer.SignRequest) bool

var filters = map[string][]filter{}
var (
	requests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "requests_total",
			Help: "How many requests for each operation type and signer were succesfully processed.",
		},
		[]string{"operation", "signer"},
	)
	erroredRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "requests_errored_total",
			Help: "How many requests for each operation type resulted in an error.",
		},
		[]string{"operation", "signer"},
	)
	badInputs = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "bad_inputs_total",
			Help: "How many times the input was malformed or not allowed.",
		},
		[]string{"operation"},
	)
)

const (
	signOperation = "sign"
)

func fail(w http.ResponseWriter, req *http.Request, status, code int, msg, ad string) {
	badInputs.WithLabelValues(signOperation).Inc()

	if ad != "" {
		ad = " (" + ad + ")"
	}
	log.Errorf("[HTTP %d] %d - %s%s", status, code, msg, ad)

	dumpReq, err := httputil.DumpRequest(req, true)
	if err != nil {
		fmt.Printf("%v#v\n", req)
	} else {
		fmt.Printf("%s\n", dumpReq)
	}

	res := api.NewErrorResponse(msg, code)
	w.WriteHeader(status)
	jenc := json.NewEncoder(w)
	jenc.Encode(res)
}

func dispatchRequest(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		fail(w, req, http.StatusMethodNotAllowed, 1, "only POST is permitted", "")
		return
	}

	defer req.Body.Close()
	body, err := io.ReadAll(req.Body)
	if err != nil {
		fail(w, req, http.StatusInternalServerError, 1, err.Error(), "while reading request body")
		return
	}

	var authReq auth.AuthenticatedRequest
	err = json.Unmarshal(body, &authReq)
	if err != nil {
		fail(w, req, http.StatusBadRequest, 1, err.Error(), "while unmarshaling request body")
		return
	}

	var sigRequest signer.SignRequest
	err = json.Unmarshal(authReq.Request, &sigRequest)
	if err != nil {
		fail(w, req, http.StatusBadRequest, 1, err.Error(), "while unmarshalling authenticated request")
		return
	}

	if sigRequest.Label == "" {
		sigRequest.Label = defaultLabel
	}

	acl := whitelists[sigRequest.Label]
	if acl != nil {
		ip, err := whitelist.HTTPRequestLookup(req)
		if err != nil {
			fail(w, req, http.StatusInternalServerError, 1, err.Error(), "while getting request IP")
			return
		}

		if !acl.Permitted(ip) {
			fail(w, req, http.StatusForbidden, 1, "not authorised", "because IP is not whitelisted")
			return
		}
	}

	s, ok := signers[sigRequest.Label]
	if !ok {
		fail(w, req, http.StatusBadRequest, 1, "bad request", "request is for non-existent label "+sigRequest.Label)
		return
	}
	requests.WithLabelValues(signOperation, sigRequest.Label).Inc()
	// Sanity checks to ensure that we have a valid policy. This
	// should have been checked in NewAuthSignHandler.
	policy := s.Policy()
	if policy == nil {
		fail(w, req, http.StatusInternalServerError, 1, "invalid policy", "signer was initialised without a signing policy")
		return
	}
	profile := policy.Default

	if policy.Profiles != nil && sigRequest.Profile != "" {
		profile = policy.Profiles[sigRequest.Profile]
		if profile == nil {
			fail(w, req, http.StatusBadRequest, 1, "invalid profile", "failed to look up profile with name: "+sigRequest.Profile)
			return
		}
	}

	if profile == nil {
		fail(w, req, http.StatusInternalServerError, 1, "invalid profile", "signer was initialised without any valid profiles")
		return
	}

	if profile.Provider == nil {
		fail(w, req, http.StatusUnauthorized, 1, "authorisation required", "received unauthenticated request")
		return
	}

	validAuth := false
	if profile.Provider.Verify(&authReq) {
		validAuth = true
	} else if profile.PrevProvider != nil && profile.PrevProvider.Verify(&authReq) {
		validAuth = true
	}
	if !validAuth {
		fail(w, req, http.StatusBadRequest, 1, "invalid token", "received authenticated request with invalid token")
		return
	}

	if sigRequest.Request == "" {
		fail(w, req, http.StatusBadRequest, 1, "invalid request", "empty request")
		return
	}

	cert, err := s.Sign(sigRequest)
	if err != nil {
		erroredRequests.WithLabelValues(signOperation, sigRequest.Label).Inc()
		fail(w, req, http.StatusBadRequest, 1, "bad request", "signature failed: "+err.Error())
		return
	}

	x509Cert, err := helpers.ParseCertificatePEM(cert)
	if err != nil {
		erroredRequests.WithLabelValues(signOperation, sigRequest.Label).Inc()
		fail(w, req, http.StatusInternalServerError, 1, "bad certificate", err.Error())
	}

	log.Infof("signature: requester=%s, label=%s, profile=%s, serialno=%s",
		req.RemoteAddr, sigRequest.Label, sigRequest.Profile, x509Cert.SerialNumber)

	res := api.NewSuccessResponse(&SignatureResponse{Certificate: string(cert)})
	jenc := json.NewEncoder(w)
	err = jenc.Encode(res)
	if err != nil {
		log.Errorf("error writing response: %v", err)
	}
}

func metricsDisallowed(w http.ResponseWriter, req *http.Request) {
	log.Warning("attempt to access metrics endpoint from external address ", req.RemoteAddr)
	http.NotFound(w, req)
}
