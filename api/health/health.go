package health

import (
	"encoding/json"
	"net/http"

	"github.com/cloudflare/cfssl/api"
)

type HealthResponse struct {
	Healthy bool `json:"healthy"`
}

func healthHandler(w http.ResponseWriter, r *http.Request) error {
	response := api.NewSuccessResponse(&HealthResponse{Healthy: true})
	return json.NewEncoder(w).Encode(response)
}

func NewHealthCheck() http.Handler {
	return api.HTTPHandler{
		Handler: api.HandlerFunc(healthHandler),
		Methods: []string{"GET"},
	}
}
