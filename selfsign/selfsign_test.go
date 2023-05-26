package selfsign

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/url"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/helpers"
)

const (
	keyFile = "testdata/localhost.key"
	csrFile = "testdata/localhost.csr"

	csr2File = "testdata/sans.csr"
)

func TestDefaultSign(t *testing.T) {
	csrBytes, err := os.ReadFile(csrFile)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}

	priv, err := helpers.ParsePrivateKeyPEM(keyBytes)
	if err != nil {
		t.Fatal(err)
	}

	profile := config.DefaultConfig()
	profile.Expiry = 10 * time.Hour

	_, err = Sign(priv, csrBytes, profile)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSANs(t *testing.T) {
	t.Skip("broken relating to https://github.com/cloudflare/cfssl/issues/1230")
	csrBytes, err := os.ReadFile(csr2File)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}

	priv, err := helpers.ParsePrivateKeyPEM(keyBytes)
	if err != nil {
		t.Fatal(err)
	}

	profile := config.DefaultConfig()
	profile.Expiry = 10 * time.Hour

	certPEM, err := Sign(priv, csrBytes, profile)
	if err != nil {
		t.Fatal(err)
	}

	p, _ := pem.Decode(certPEM)
	if p == nil || p.Type != "CERTIFICATE" {
		// this seems unlikely
		t.Fatalf("failed creating certificate")
	}

	cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	expectedEmailAddresses := []string{"jdoe@example.com"}
	if !reflect.DeepEqual(cert.EmailAddresses, expectedEmailAddresses) {
		t.Errorf("cert should have contained EmailAddresses %#v but had %#v", expectedEmailAddresses, cert.EmailAddresses)
	}

	expectedDNSNames := []string{"cloudflare.com", "www.cloudflare.com"}
	if !reflect.DeepEqual(cert.DNSNames, expectedDNSNames) {
		t.Errorf("cert should have contained DNSNames %#v but had %#v", expectedDNSNames, cert.DNSNames)
	}

	expectedIPAddresses := []net.IP{{0xc0, 0xa8, 0x0, 0x1}}
	if !reflect.DeepEqual(cert.IPAddresses, expectedIPAddresses) {
		t.Errorf("cert should have contained IPAddresses %#v but had %#v", expectedIPAddresses, cert.IPAddresses)
	}

	expectedURIs := []*url.URL{{Scheme: "https", Host: "www.cloudflare.com"}}
	if !reflect.DeepEqual(cert.URIs, expectedURIs) {
		t.Errorf("cert should have contained URIs %#v but had %#v", expectedURIs, cert.URIs)
	}

}
