package ocsp

import (
	"io/ioutil"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/cloudflare/cfssl/helpers"
)

const (
	serverCertFile      = "testdata/ca.pem"
	serverKeyFile       = "testdata/ca-key.pem"
	otherCertFile       = "testdata/cert.pem"
	brokenServerCert    = "testdata/server_broken.crt"
	brokenServerKey     = "testdata/server_broken.key"
	wrongServerCertFile = "testdata/server.crt"
	wrongServerKeyFile  = "testdata/server.key"
	responseFile        = "testdata/resp64.pem"
	binResponseFile     = "testdata/response.pem"
	brokenResponseFile  = "testdata/response_broken.pem"
	mixResponseFile     = "testdata/response_mix.pem"
)

func TestNewSignerFromFile(t *testing.T) {
	// arbitrary duration
	dur, _ := time.ParseDuration("1ms")

	// nonexistent files
	_, err := NewSignerFromFile("", "", "", dur)
	if err == nil {
		t.Fatal("Failed to issue error on improper file")
	}

	_, err = NewSignerFromFile(serverCertFile, "", "", dur)
	if err == nil {
		t.Fatal("Failed to issue error on improper file")
	}

	_, err = NewSignerFromFile(serverCertFile, otherCertFile, "", dur)
	if err == nil {
		t.Fatal("Failed to issue error on improper file")
	}

	// malformed certs
	_, err = NewSignerFromFile(brokenServerCert, otherCertFile, serverKeyFile, dur)
	if err == nil {
		t.Fatal("Didn't fail on malformed file")
	}

	_, err = NewSignerFromFile(serverCertFile, brokenServerCert, serverKeyFile, dur)
	if err == nil {
		t.Fatal("Didn't fail on malformed file")
	}

	_, err = NewSignerFromFile(serverCertFile, otherCertFile, brokenServerKey, dur)
	if err == nil {
		t.Fatal("Didn't fail on malformed file")
	}

	// expected case
	_, err = NewSignerFromFile(serverCertFile, otherCertFile, serverKeyFile, dur)
	if err != nil {
		t.Fatalf("Signer creation failed %v", err)
	}
}

func setup(t *testing.T) (SignRequest, time.Duration) {
	dur, _ := time.ParseDuration("1ms")
	certPEM, err := ioutil.ReadFile(otherCertFile)
	if err != nil {
		t.Fatal(err)
	}

	leafCert, err := helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}

	req := SignRequest{
		Certificate: leafCert,
		Status:      "good",
	}
	return req, dur
}

func TestSignNoResponder(t *testing.T) {
	req, dur := setup(t)
	s, err := NewSignerFromFile(serverCertFile, serverCertFile, serverKeyFile, dur)
	if err != nil {
		t.Fatalf("Signer creation failed: %v", err)
	}
	respBytes, err := s.Sign(req)
	if err != nil {
		t.Fatal("Failed to sign with no responder cert")
	}

	resp, err := ocsp.ParseResponse(respBytes, nil)
	if err != nil {
		t.Fatal("Failed to fail on improper status code")
	}
	if resp.Certificate != nil {
		t.Fatal("Response contain responder cert even though it was identical to issuer")
	}
}

func TestSign(t *testing.T) {
	req, dur := setup(t)

	// expected case
	s, err := NewSignerFromFile(serverCertFile, otherCertFile, serverKeyFile, dur)
	if err != nil {
		t.Fatalf("Signer creation failed: %v", err)
	}

	_, err = s.Sign(SignRequest{})
	if err == nil {
		t.Fatal("Signed request with nil certificate")
	}

	_, err = s.Sign(req)
	if err != nil {
		t.Fatal("Sign failed")
	}

	sMismatch, err := NewSignerFromFile(wrongServerCertFile, otherCertFile, wrongServerKeyFile, dur)
	_, err = sMismatch.Sign(req)
	if err == nil {
		t.Fatal("Signed a certificate from the wrong issuer")
	}

	// incorrect status code
	req.Status = "aalkjsfdlkafdslkjahds"
	_, err = s.Sign(req)
	if err == nil {
		t.Fatal("Failed to fail on improper status code")
	}

	// revoked
	req.Status = "revoked"
	_, err = s.Sign(req)
	if err != nil {
		t.Fatal("Error on revoked certificate")
	}
}

func TestNewSourceFromFile(t *testing.T) {
	_, err := NewSourceFromFile("", nil)
	if err == nil {
		t.Fatal("Didn't fail on non-file input")
	}

	// expected case
	_, err = NewSourceFromFile(responseFile, nil)
	if err != nil {
		t.Fatal(err)
	}

	// binary-formatted file
	_, err = NewSourceFromFile(binResponseFile, nil)
	if err != nil {
		t.Fatal(err)
	}

	// the response file from before, with stuff deleted
	_, err = NewSourceFromFile(brokenResponseFile, nil)
	if err != nil {
		t.Fatal(err)
	}

	// mix of a correct and malformed responses
	_, err = NewSourceFromFile(mixResponseFile, nil)
	if err != nil {
		t.Fatal(err)
	}
}
