package csr

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"
)

func TestGenerateRawSubject(t *testing.T) {
	raw := []byte{0x30, 0x0e, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x03, 'a', 'b', 'c'}
	req := &CertificateRequest{RawSubject: raw}
	csrPEM, _, err := ParseRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(csrPEM)
	parsed, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed.RawSubject, raw) {
		t.Errorf("RawSubject = % x, want % x", parsed.RawSubject, raw)
	}
}

func TestGenerateRawSubjectConflicts(t *testing.T) {
	raw := []byte{0x30, 0x00}
	for _, req := range []*CertificateRequest{
		{RawSubject: raw, CN: "x"},
		{RawSubject: raw, Names: []Name{{O: "x"}}},
		{RawSubject: raw, SerialNumber: "1"},
		{RawSubject: []byte{0x04, 0x00}},
		{RawSubject: append(raw, 0)},
		{RawSubject: raw},
		{RawSubject: []byte{0x30, 0x02, 0x31, 0x00}},             // empty SET
		{RawSubject: []byte{0x30, 0x04, 0x31, 0x02, 0x04, 0x00}}, // SET of OCTET STRING
		{RawSubject: []byte{0x30, 0x09, 0x31, 0x07, 0x30, 0x05, 0x06, 0x03, 0x55, 0x04, 0x03}},                         // attribute without value
		{RawSubject: []byte{0x30, 0x0d, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x00, 0x0c, 0x00}}, // two values
	} {
		if _, _, err := ParseRequest(req); err == nil {
			t.Errorf("ParseRequest(%+v) succeeded, want error", req)
		}
	}
}

func TestRawSubjectIsNotRequestInput(t *testing.T) {
	// base64 of the DER Name 30 00 0b..., a CN of "evil".
	const input = `{"raw_subject": "MA8xDTALBgNVBAMMBGV2aWw=", "key": {"algo": "ecdsa", "size": 256}}`
	var req CertificateRequest
	if err := json.Unmarshal([]byte(input), &req); err != nil {
		t.Fatal(err)
	}
	if len(req.RawSubject) != 0 {
		t.Errorf("JSON input set RawSubject to % x", req.RawSubject)
	}

	out, err := json.Marshal(&CertificateRequest{RawSubject: []byte{0x30, 0x00}})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("raw_subject")) {
		t.Errorf("JSON output %s contains raw_subject", out)
	}
}
