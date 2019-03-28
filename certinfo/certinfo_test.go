package certinfo

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/certdb/sql"
	"github.com/cloudflare/cfssl/certdb/testdb"
)

const (
	sqliteDBFile = "../certdb/testdb/certstore_development.db"
	fakeAKI      = "fake_aki"
	testSerial   = 1337
)

func TestParseSerialNumber(t *testing.T) {
	db := testdb.SQLiteDB(sqliteDBFile)
	accessor := sql.NewAccessor(db)

	certificate, err := createCertificate()
	if err != nil {
		t.Logf("could not create certificate: %s", err.Error())
		t.FailNow()
	}

	err = accessor.InsertCertificate(
		certdb.CertificateRecord{
			Serial: big.NewInt(testSerial).String(),
			AKI:    fakeAKI,
			PEM:    certificate,
		},
	)

	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}

	cases := []struct {
		description        string
		serial             string
		aki                string
		errorShouldContain string
	}{
		{
			description:        "no certificate found - wrong serial",
			serial:             "1",
			aki:                fakeAKI,
			errorShouldContain: "no certificate found",
		},
		{
			description:        "no certificate found - wrong AKI",
			serial:             "123456789",
			aki:                "1",
			errorShouldContain: "no certificate found",
		},
		{
			description: "certificate found",
			serial:      big.NewInt(testSerial).String(),
			aki:         fakeAKI,
		},
	}

	for _, tc := range cases {
		t.Run(tc.description, func(t *testing.T) {
			cert, err := ParseSerialNumber(tc.serial, tc.aki, accessor)

			if tc.errorShouldContain != "" {
				if cert != nil {
					t.Error("no certificate should be returned if error occurs")
				}

				if err == nil {
					t.Error("err expected to not be nil")

					return
				}

				if !strings.Contains(err.Error(), tc.errorShouldContain) {
					t.Errorf("expected error to contain '%s' but was '%s'", tc.errorShouldContain, err.Error())
				}

				return
			}

			if err != nil {
				t.Errorf("expected error to be nil but got '%s'", err.Error())

				return
			}

			if cert.SerialNumber != tc.serial {
				t.Errorf("returned certificate doesn't match the serial queried for")
			}
		})
	}
}

func createCertificate() (string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(testSerial),
		Subject: pkix.Name{
			Country:      []string{"SE"},
			Organization: []string{"CFSSL Unit Testing"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	certificate, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		return "", err
	}

	return certificateToPEMBlock(certificate)
}

func certificateToPEMBlock(cert []byte) (string, error) {
	buf := &bytes.Buffer{}

	err := pem.Encode(buf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})

	if err != nil {
		return "", err
	}

	return buf.String(), nil
}
