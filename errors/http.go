package errors

import (
	"errors"
	"net/http"
)

// HttpError is an augmented error with a HTTP status code.
type HttpError struct {
	StatusCode int
	error
}

// The error interface implementation
func (e *HttpError) Error() string {
	return e.error.Error()
}

func NewMethodNotAllowed(method string) *HttpError {
	return &HttpError{http.StatusMethodNotAllowed, errors.New(`Method is not allowed:"` + method + `"`)}
}

// NewBadRequest creates a HttpError with the given error and error code 400.
func NewBadRequest(err error) *HttpError {
	return &HttpError{http.StatusBadRequest, err}
}

// NewBadRequestString returns a HttpError with the supplied message
// and error code 400.
func NewBadRequestString(s string) *HttpError {
	return NewBadRequest(errors.New(s))
}

// NewBadRequestMissingParameter returns a 400 HttpError as a required
// parameter is missing in the HTTP request.
func NewBadRequestMissingParameter(s string) *HttpError {
	return NewBadRequestString(`Missing parameter "` + s + `"`)
}

// NewBadRequestUnwantedParameter returns a 400 HttpError as a unnecessary
// parameter is present in the HTTP request.
func NewBadRequestUnwantedParameter(s string) *HttpError {
	return NewBadRequestString(`Unwanted parameter "` + s + `"`)
}
