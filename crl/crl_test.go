package crl

import (
	"crypto/x509"
	"math/big"
	"os"
	"testing"
)

const (
	serverCertFile = "testdata/ca.pem"
	serverKeyFile  = "testdata/ca-key.pem"
	tryTwoCert     = "testdata/caTwo.pem"
	tryTwoKey      = "testdata/ca-keyTwo.pem"
	serialList     = "testdata/serialList"
)

func TestNewCRLFromFile(t *testing.T) {

	tryTwoKeyBytes, err := os.ReadFile(tryTwoKey)
	if err != nil {
		t.Fatal(err)
	}

	tryTwoCertBytes, err := os.ReadFile(tryTwoCert)
	if err != nil {
		t.Fatal(err)
	}

	serialListBytes, err := os.ReadFile(serialList)
	if err != nil {
		t.Fatal(err)
	}

	crl, err := NewCRLFromFile(serialListBytes, tryTwoCertBytes, tryTwoKeyBytes, "0", big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}

	certList, err := x509.ParseRevocationList(crl)
	if err != nil {
		t.Fatal(err)
	}

	numCerts := len(certList.RevokedCertificateEntries)
	expectedNum := 4
	if expectedNum != numCerts {
		t.Fatal("Wrong number of expired certificates")
	}

	if big.NewInt(1).Cmp(certList.Number) != 0 {
		t.Fatal("Wrong CRL number")
	}
}

func TestNewCRLFromFileWithoutRevocations(t *testing.T) {
	tryTwoKeyBytes, err := os.ReadFile(tryTwoKey)
	if err != nil {
		t.Fatal(err)
	}

	tryTwoCertBytes, err := os.ReadFile(tryTwoCert)
	if err != nil {
		t.Fatal(err)
	}

	crl, err := NewCRLFromFile([]byte("\n \n"), tryTwoCertBytes, tryTwoKeyBytes, "0", big.NewInt(0))
	if err != nil {
		t.Fatal(err)
	}

	certList, err := x509.ParseRevocationList(crl)
	if err != nil {
		t.Fatal(err)
	}

	numCerts := len(certList.RevokedCertificateEntries)
	expectedNum := 0
	if expectedNum != numCerts {
		t.Fatal("Wrong number of expired certificates")
	}

	if big.NewInt(0).Cmp(certList.Number) != 0 {
		t.Fatal("Wrong CRL number")
	}
}
