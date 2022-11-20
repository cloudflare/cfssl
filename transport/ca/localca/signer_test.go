package localca

import (
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/initca"
)

func TestEncodePEM(t *testing.T) {
	p := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: []byte(`¯\_(ツ)_/¯`),
	}
	t.Logf("PEM:\n%s\n\n", string(pem.EncodeToMemory(p)))
}

func TestLoadSigner(t *testing.T) {
	lca := &CA{}
	certPEM, csrPEM, keyPEM, err := initca.New(ExampleRequest())
	if err != nil {
		t.Fatal(err)
	}

	_, err = lca.CACertificate()
	if !errors.Is(err, errNotSetup) {
		t.Fatalf("expected an errNotSetup (%v), got: %v", errNotSetup, err)
	}

	_, err = lca.SignCSR(csrPEM)
	if !errors.Is(err, errNotSetup) {
		t.Fatalf("expected an errNotSetup (%v), got: %v", errNotSetup, err)
	}

	tmpDir := t.TempDir()
	lca.KeyFile = filepath.Join(tmpDir, "KeyFile")
	lca.CertFile = filepath.Join(tmpDir, "CertFile")

	err = os.WriteFile(lca.KeyFile, keyPEM, 0644)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(lca.CertFile, certPEM, 0644)
	if err != nil {
		t.Fatal(err)
	}

	err = Load(lca, ExampleSigningConfig())
	if err != nil {
		t.Fatal(err)
	}
}

var testRequest = &csr.CertificateRequest{
	CN: "Transport Test Identity",
	KeyRequest: &csr.KeyRequest{
		A: "ecdsa",
		S: 256,
	},
	Hosts: []string{"127.0.0.1"},
}

func TestNewSigner(t *testing.T) {
	req := ExampleRequest()
	lca, err := New(req, ExampleSigningConfig())
	if err != nil {
		t.Fatal(err)
	}

	csrPEM, _, err := csr.ParseRequest(testRequest)
	if err != nil {
		t.Fatal(err)
	}

	certPEM, err := lca.SignCSR(csrPEM)
	if err != nil {
		t.Fatal(err)
	}

	_, err = helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}

	certPEM, err = lca.CACertificate()
	if err != nil {
		t.Fatal(err)
	}

	cert, err := helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}

	if cert.Subject.CommonName != req.CN {
		t.Fatalf("common names don't match: '%s' != '%s'", cert.Subject.CommonName, req.CN)
	}

	lca.Toggle()
	_, err = lca.SignCSR(csrPEM)
	if !errors.Is(err, errDisabled) {
		t.Fatalf("expected an errDisabled (%v), got: %v", errDisabled, err)
	}
	lca.Toggle()

	_, err = lca.SignCSR(certPEM)
	if err == nil {
		t.Fatal("shouldn't be able to sign non-CSRs")
	}

	p := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: []byte(`¯\_(ツ)_/¯`),
	}
	junkCSR := pem.EncodeToMemory(p)

	_, err = lca.SignCSR(junkCSR)
	if err == nil {
		t.Fatal("signing a junk CSR should fail")
	}
	t.Logf("error: %s", err)
}
