package selfsign

import (
	"crypto/x509"
	"encoding/pem"
	"encoding/asn1"
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

	extCsrFile = "testdata/extension.csr"
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

func TestExtensions(t *testing.T){
	csrBytes, err := os.ReadFile(extCsrFile)
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

	certData, err := Sign(priv, csrBytes, profile)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := helpers.ParseCertificatePEM(certData)
	if err != nil {
		t.Fatal(err)
	}

	// Testing for 1.3.6.1.4.1.311.84.1.1=ASN1:UTF8String:example1
	extFound := false
	sampleCustomOid := asn1.ObjectIdentifier{1,3,6,1,4,1,311,84,1,1}
	sampleValue := "example1"

	for _, e := range cert.Extensions {
		if(e.Id.Equal(sampleCustomOid) ){
			var extValue string
			_, err = asn1.Unmarshal(e.Value, &extValue)
			if err != nil {
				t.Fatal(err)
			}
			if(extValue == sampleValue){
				extFound = true
			}
		}
	}

	if !extFound {
		t.Errorf("Custom x509 extension not found in certificate.")
	}
}
