package healthz

import (
	"encoding/json"
	"net/http"

	"github.com/cloudflare/cfssl/api"
)

type HealthzResponse struct {
	Healthy bool `json:"healthy"`
}

func healthzHandler(w http.ResponseWriter, r *http.Request) error {
	response := api.NewSuccessResponse(&HealthzResponse{Healthy: true})
	return json.NewEncoder(w).Encode(response)
}

func NewHealthCheck() http.Handler {
	return api.HTTPHandler{
		Handler: api.HandlerFunc(healthzHandler),
		Methods: []string{"GET"},
	}
}
