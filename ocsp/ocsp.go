// Package signer implements certificate signature functionality for CF-SSL.
package ocsp

import (
	"errors"
)

// TODO
type SignRequest struct{}

type Signer interface {
	Sign(req SignRequest) ([]byte, error)
}

// TODO
type StandardSigner struct{}

// TODO
func (s StandardSigner) Sign(req SignRequest) ([]byte, error) {
	return nil, errors.New("OCSP has not been implemented")
}

func NewSigner() Signer {
	return StandardSigner{}
}
