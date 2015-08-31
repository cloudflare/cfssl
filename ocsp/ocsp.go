/*

Package ocsp exposes OCSP signing functionality, much like the signer
package does for certificate signing.  It also provies a basic OCSP
responder stack for serving pre-signed OCSP responses.

*/
package ocsp

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"io/ioutil"
	"time"

	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	"golang.org/x/crypto/ocsp"
)

// StatusCode is a map between string statuses sent by cli/api
// to ocsp int statuses
var StatusCode = map[string]int{
	"good":    ocsp.Good,
	"revoked": ocsp.Revoked,
	"unknown": ocsp.Unknown,
}

// SignRequest represents the desired contents of a
// specific OCSP response.
type SignRequest struct {
	Certificate *x509.Certificate
	Status      string
	Reason      int
	RevokedAt   time.Time
}

// Signer represents a general signer of OCSP responses.  It is
// responsible for populating all fields in the OCSP response that
// are not reflected in the SignRequest.
type Signer interface {
	Sign(req SignRequest) ([]byte, error)
}

// StandardSigner is the default concrete type of OCSP signer.
// It represents a single responder (represented by a key and certificate)
// speaking for a single issuer (certificate).  It is assumed that OCSP
// responses are issued at a regular interval, which is used to compute
// the nextUpdate value based on the current time.
type StandardSigner struct {
	issuer    *x509.Certificate
	responder *x509.Certificate
	key       crypto.Signer
	interval  time.Duration
}

// NewSignerFromFile reads the issuer cert, the responder cert and the responder key
// from PEM files, and takes an interval in seconds
func NewSignerFromFile(issuerFile, responderFile, keyFile string, interval time.Duration) (Signer, error) {
	log.Debug("Loading issuer cert: ", issuerFile)
	issuerBytes, err := ioutil.ReadFile(issuerFile)
	if err != nil {
		return nil, err
	}
	log.Debug("Loading responder cert: ", responderFile)
	responderBytes, err := ioutil.ReadFile(responderFile)
	if err != nil {
		return nil, err
	}
	log.Debug("Loading responder key: ", keyFile)
	keyBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, cferr.Wrap(cferr.CertificateError, cferr.ReadFailed, err)
	}

	issuerCert, err := helpers.ParseCertificatePEM(issuerBytes)
	if err != nil {
		return nil, err
	}

	responderCert, err := helpers.ParseCertificatePEM(responderBytes)
	if err != nil {
		return nil, err
	}

	key, err := helpers.ParsePrivateKeyPEM(keyBytes)
	if err != nil {
		log.Debug("Malformed private key %v", err)
		return nil, err
	}

	return NewSigner(issuerCert, responderCert, key, interval)
}

// NewSigner simply constructs a new StandardSigner object from the inputs,
// taking the interval in seconds
func NewSigner(issuer, responder *x509.Certificate, key crypto.Signer, interval time.Duration) (Signer, error) {
	return &StandardSigner{
		issuer:    issuer,
		responder: responder,
		key:       key,
		interval:  interval,
	}, nil
}

// Sign is used with an OCSP signer to request the issuance of
// an OCSP response.
func (s StandardSigner) Sign(req SignRequest) ([]byte, error) {
	if req.Certificate == nil {
		return nil, cferr.New(cferr.OCSPError, cferr.ReadFailed)
	}

	// Verify that req.Certificate is issued under s.issuer
	if bytes.Compare(req.Certificate.RawIssuer, s.issuer.RawSubject) != 0 {
		return nil, cferr.New(cferr.OCSPError, cferr.IssuerMismatch)
	}
	if req.Certificate.CheckSignatureFrom(s.issuer) != nil {
		return nil, cferr.New(cferr.OCSPError, cferr.IssuerMismatch)
	}

	// Round thisUpdate times down to the nearest hour
	thisUpdate := time.Now().Truncate(time.Hour)
	nextUpdate := thisUpdate.Add(s.interval)

	status, ok := StatusCode[req.Status]
	if !ok {
		return nil, cferr.New(cferr.OCSPError, cferr.InvalidStatus)
	}

	template := ocsp.Response{
		Status:       status,
		SerialNumber: req.Certificate.SerialNumber,
		ThisUpdate:   thisUpdate,
		NextUpdate:   nextUpdate,
		Certificate:  s.responder,
	}

	if status == ocsp.Revoked {
		template.RevokedAt = req.RevokedAt
		template.RevocationReason = req.Reason
	}

	return ocsp.CreateResponse(s.issuer, s.responder, template, s.key)
}
