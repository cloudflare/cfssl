package errors

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"testing"
)

func TestNew(t *testing.T) {
	err := New(CertificateError, Unknown)
	if err == nil {
		t.Fatal("Error creation failed.")
	}
	if err.ErrorCode != int(CertificateError)+int(Unknown) {
		t.Fatal("Error code construction failed.")
	}
	if err.Message != "Unknown certificate error" {
		t.Fatal("Error message construction failed.")
	}
}

func TestWrap(t *testing.T) {
	msg := "Arbitrary error message"
	err := Wrap(CertificateError, Unknown, errors.New(msg))
	if err == nil {
		t.Fatal("Error creation failed.")
	}
	if err.ErrorCode != int(CertificateError)+int(Unknown) {
		t.Fatal("Error code construction failed.")
	}
	if err.Message != msg {
		t.Fatal("Error message construction failed.")
	}

	err = Wrap(CertificateError, VerifyFailed, x509.CertificateInvalidError{Reason: x509.Expired})
	if err == nil {
		t.Fatal("Error creation failed.")
	}
	if err.ErrorCode != int(CertificateError)+int(VerifyFailed)+certificateInvalid+int(x509.Expired) {
		t.Fatal("Error code construction failed.")
	}
	if err.Message != "x509: certificate has expired or is not yet valid" {
		t.Fatal("Error message construction failed.")
	}
}

func TestMarshal(t *testing.T) {
	msg := "Arbitrary error message"
	err := Wrap(CertificateError, Unknown, errors.New(msg))
	bytes, _ := json.Marshal(err)
	var received Error
	json.Unmarshal(bytes, &received)
	if received.ErrorCode != int(CertificateError)+int(Unknown) {
		t.Fatal("Error code construction failed.")
	}
	if received.Message != msg {
		t.Fatal("Error message construction failed.")
	}
}

func TestErrorString(t *testing.T) {
	msg := "Arbitrary error message"
	err := Wrap(CertificateError, Unknown, errors.New(msg))
	str := err.Error()
	if str != `{"code":1000,"message":"`+msg+`"}` {
		t.Fatal("Incorrect Error():", str)
	}
}
