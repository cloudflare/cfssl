package scan

import (
	"encoding/json"
	"net/http"

	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/scan"
)

// scanHandler is an HTTP handler that accepts GET parameters for host (required)
// family and scanner, and uses these to perform scans, returning a JSON blob result.
func scanHandler(w http.ResponseWriter, r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		log.Warningf("failed to parse body: %v", err)
		return errors.NewBadRequest(err)
	}

	if len(r.Form["host"]) == 0 {
		log.Warningf("no host given")
		return errors.NewBadRequestString("no host given")
	}
	host := r.Form["host"][0]

	var family, scanner string
	if len(r.Form["family"]) > 0 {
		family = r.Form["family"][0]
	}

	if len(r.Form["scanner"]) > 0 {
		scanner = r.Form["scanner"][0]
	}

	resChan := make(chan scan.PackagedFamilyResult)
	errChan := make(chan error)
	done := make(chan bool)

	results := make(map[string]scan.FamilyResult)
	go scan.Default.RunScans(host, family, scanner, resChan, errChan)

	go func() {
		for res := range resChan {
			results[res.FamilyName] = res.Result
		}
		done <- true
	}()

	e := <-errChan
	if e != nil {
		return errors.NewBadRequest(e)
	}
	<-done

	response := api.NewSuccessResponse(results)
	enc := json.NewEncoder(w)
	return enc.Encode(response)
}

// NewHandler returns a new http.Handler that handles a scan request.
func NewHandler() http.Handler {
	return api.HTTPHandler{
		Handler: api.HandlerFunc(scanHandler),
		Methods: []string{"GET"},
	}
}

// scanInfoHandler is an HTTP handler that returns a JSON blob result describing
// the possible families and scans to be run.
func scanInfoHandler(w http.ResponseWriter, r *http.Request) error {
	log.Info("setting up scaninfo handler")
	response := api.NewSuccessResponse(scan.Default)
	enc := json.NewEncoder(w)
	return enc.Encode(response)
}

// NewInfoHandler returns a new http.Handler that handles a request for scan info.
func NewInfoHandler() http.Handler {
	return api.HTTPHandler{Handler: api.HandlerFunc(scanInfoHandler), Methods: []string{"GET"}}
}
