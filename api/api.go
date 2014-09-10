// Package api implements an HTTP-based API and server for CF-SSL.
package api

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/log"
)

// Handler is an interface providing a generic mechanism for handling HTTP requests.
type Handler interface {
	Handle(w http.ResponseWriter, r *http.Request) error
}

// HTTPHandler is a wrapper that encapsulates Handler interface as http.Handler.
// HttpHandler also enforces that the Handler only responds to requests with registered HTTP method.
type HTTPHandler struct {
	Handler        // CFSSL handler
	Method  string // The assoicated HTTP method
}

// HandlerFunc is similar to the http.HandlerFunc type; it serves as
// an adapter allowing the use of ordinary functions as Handlers. If
// f is a function with the appropriate signature, HandlerFunc(f) is a
// Handler object that calls f.
type HandlerFunc func(http.ResponseWriter, *http.Request) error

// Handle calls f(w, r)
func (f HandlerFunc) Handle(w http.ResponseWriter, r *http.Request) error {
	return f(w, r)
}

// handleError is the centralised error handling and reporting.
func handleError(w http.ResponseWriter, err error) (code int) {
	if err == nil {
		return http.StatusOK
	}
	msg := err.Error()
	code = http.StatusInternalServerError
	// If it is recognized as HttpError emitted from cf-ssl,
	// we rewrite the status code accordingly.
	if err, ok := err.(*errors.HTTPError); ok && err.StatusCode != 0 {
		code = err.StatusCode
	}

	response := newErrorResponse(msg, code)
	jsonMessage, err := json.Marshal(response)
	if err != nil {
		log.Errorf("Failed to marshal JSON: %v", err)
	} else {
		msg = string(jsonMessage)
	}
	http.Error(w, msg, code)
	return code
}

// ServeHTTP encapsulates the call to underlying Handler to handle the request
// and return the response with proper HTTP status code
func (h HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var err error
	// Throw 405 when requested with an unsupported verb.
	if r.Method != h.Method {
		err = errors.NewMethodNotAllowed(r.Method)
	} else {
		err = h.Handle(w, r)
	}
	status := handleError(w, err)
	log.Infof("%s - \"%s %s\" %d", r.RemoteAddr, r.Method, r.URL, status)
}

// readRequestBlob takes a JSON-blob-encoded response body in the form
// map[string]string and returns it, the list of keywords presented,
// and any error that occurred.
func readRequestBlob(r *http.Request) (map[string]string, error) {
	var blob map[string]string

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	r.Body.Close()

	err = json.Unmarshal(body, &blob)
	if err != nil {
		return nil, err
	}
	return blob, nil
}

// processRequestOneOf reads a JSON blob for the request and makes
// sure it contains one of a set of keywords. For example, a request
// might have the ('foo' && 'bar') keys, OR it might have the 'baz'
// key.  In either case, we want to accept the request; however, if
// none of these sets shows up, the request is a bad request, and it
// should be returned.
func processRequestOneOf(r *http.Request, keywordSets [][]string) (map[string]string, []string, error) {
	blob, err := readRequestBlob(r)
	if err != nil {
		return nil, nil, err
	}

	var matched []string
	for _, set := range keywordSets {
		if matchKeywords(blob, set) {
			if matched != nil {
				return nil, nil, errors.NewBadRequestString("mismatched parameters")
			}
			matched = set
		}
	}
	if matched == nil {
		return nil, nil, errors.NewBadRequestString("no valid parameter sets found")
	}
	return blob, matched, nil
}

func missingParamsError(missing []string) error {
	s := "Missing parameter"
	if len(missing) > 1 {
		s += "s"
	}
	s += " "
	s += strings.Join(missing, ", ")
	return errors.NewBadRequestString(s)
}

func matchKeywords(blob map[string]string, keywords []string) bool {
	for _, keyword := range keywords {
		if _, ok := blob[keyword]; !ok {
			return false
		}
	}
	return true
}

// ResponseMessage implements the standard for response errors and
// messages. A message has a code and a string message.
type ResponseMessage struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Response implements the CloudFlare standard for API
// responses. CFSSL does not currently use the messages field, but it
// is provided for compatability.
type Response struct {
	Success  bool              `json:"success"`
	Result   interface{}       `json:"result"`
	Errors   []ResponseMessage `json:"errors"`
	Messages []ResponseMessage `json:"messages"`
}

// newResponseSuccess is a shortcut for creating new successul API
// responses. CFSSL does not use the messages field, but it is
// provided to conform to the CloudFlare standard.
func newSuccessResponse(result interface{}) Response {
	return Response{
		Success:  true,
		Result:   result,
		Errors:   []ResponseMessage{},
		Messages: []ResponseMessage{},
	}
}

// newErrorResponse is a shortcut for creating an error response for a
// single error.
func newErrorResponse(message string, code int) Response {
	return Response{
		Success:  false,
		Result:   nil,
		Errors:   []ResponseMessage{{code, message}},
		Messages: []ResponseMessage{},
	}
}

// sendResponse builds a response from the result, sets the JSON
// header, and writes to the http.ResponseWriter.
func sendResponse(w http.ResponseWriter, result interface{}) error {
	response := newSuccessResponse(result)
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	err := enc.Encode(response)
	return err
}
