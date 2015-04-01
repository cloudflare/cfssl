package scan

import (
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"

	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/scan"
)

// Request contatins a request to perform scan(s) on the given hosts.
type Request struct {
	Hosts   []string `json:"hosts"`
	Scanner string   `json:"scanner,optional"`
	Family  string   `json:"family,optional"`
}

// ScannerResult contains the result for a single scan.
type ScannerResult struct {
	Scanner     string      `json:"scanner"`
	Description string      `json:"description"`
	Grade       scan.Grade  `json:"grade"`
	Output      scan.Output `json:"output"`
	Error       error       `json:"error,omitempty"`
}

// FamilyResponse contains a scan response for a single Family
type FamilyResponse struct {
	Family      string          `json:"family"`
	Description string          `json:"description"`
	Results     []ScannerResult `json:"results"`
}

// scanHandler is an HTTP handler that accepts a JSON blob
func scanHandler(w http.ResponseWriter, r *http.Request) error {
	log.Info("setting up scan handler")

	req := new(Request)
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

	familyRegexp, err := regexp.Compile(req.Family)
	scannerRegexp, err := regexp.Compile(req.Scanner)
	if err != nil {
		log.Warningf("failed to compile regexp: %v", err)
		return errors.NewBadRequest(err)
	}

	responses := make(map[string][]FamilyResponse)
	for _, host := range req.Hosts {
		if _, _, err := net.SplitHostPort(host); err != nil {
			host = net.JoinHostPort(host, "443")
		}

		for _, family := range scan.AllFamilies {
			if familyRegexp.MatchString(family.Name) {
				fr := FamilyResponse{Family: family.Name, Description: family.Description}
				for _, scanner := range family.Scanners {
					if scannerRegexp.MatchString(scanner.Name) {
						sr := ScannerResult{Scanner: scanner.Name, Description: scanner.Description}
						sr.Grade, sr.Output, sr.Error = scanner.Scan(host)
						fr.Results = append(fr.Results, sr)
						if sr.Error != nil {
							log.Warningf("error performing %s scan: %v", scanner.Name, sr.Error)
						}
					}
				}
				responses[host] = append(responses[host], fr)
			}
		}
	}

	response := api.NewSuccessResponse(responses)
	enc := json.NewEncoder(w)
	err = enc.Encode(response)
	return err
}

// NewHandler returns a new http.Handler that handles request to
// initialize a CA.
func NewHandler() http.Handler {
	return api.HTTPHandler{Handler: api.HandlerFunc(scanHandler), Method: "POST"}
}
