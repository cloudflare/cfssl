package helpers

import (
	"io/ioutil"
	"testing"
)

const (
	testCertFile          = "testdata/cert.pem"
	testBundleFile        = "testdata/bundle.pem"
	testExtraWSCertFile   = "testdata/cert_with_whitespace.pem"
	testExtraWSBundleFile = "testdata/bundle_with_whitespace.pem"
)

func TestParseCertificatePEM(t *testing.T) {
	for _, testFile := range []string{testCertFile, testExtraWSCertFile} {
		certPEM, err := ioutil.ReadFile(testFile)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := ParseCertificatePEM(certPEM); err != nil {
			t.Fatal(err)
		}
	}
}

func TestParseCertificatesPEM(t *testing.T) {
	for _, testFile := range []string{testBundleFile, testExtraWSBundleFile} {
		bundlePEM, err := ioutil.ReadFile(testFile)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := ParseCertificatesPEM(bundlePEM); err != nil {
			t.Fatal(err)
		}
	}
}
