package crl

import (
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/certdb/sql"
	"github.com/cloudflare/cfssl/certdb/testdb"
	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/helpers"
)

var dbAccessor certdb.Accessor

const (
	fakeAKI       = "fake aki"
	testCaFile    = "../testdata/ca.pem"
	testCaKeyFile = "../testdata/ca-key.pem"
)

func prepDB() (err error) {
	db := testdb.SQLiteDB("../../certdb/testdb/certstore_development.db")
	expirationTime := time.Now().AddDate(1, 0, 0)
	var cert = certdb.CertificateRecord{
		Serial:    "1",
		AKI:       fakeAKI,
		Expiry:    expirationTime,
		PEM:       "revoked cert",
		Status:    "revoked",
		RevokedAt: time.Now(),
		Reason:    4,
	}

	dbAccessor = sql.NewAccessor(db)
	err = dbAccessor.InsertCertificate(cert)
	if err != nil {
		return err
	}

	return
}

func verifyCRL(t *testing.T, crlBytesDER []byte, serial string, expireAfter time.Duration, number *big.Int) {
	parsedCrl, err := x509.ParseRevocationList(crlBytesDER)
	if err != nil {
		t.Fatal("failed to get certificate ", err)
	}
	if !parsedCrl.NextUpdate.Before(time.Now().Add(expireAfter)) {
		t.Fatalf("the CRL should have expired")
	}
	certs := parsedCrl.RevokedCertificateEntries
	if len(certs) != 1 {
		t.Fatal("failed to get one certificate")
	}

	cert := certs[0]

	if cert.SerialNumber.String() != serial {
		t.Fatal("cert was not correctly inserted in CRL, serial was " + cert.SerialNumber.String())
	}

	if number.Cmp(parsedCrl.Number) != 0 {
		t.Fatalf("CRL number was incorrect: %s, expect: %s", parsedCrl.Number, number)
	}
}

func TestRevokeMain(t *testing.T) {
	err := prepDB()
	if err != nil {
		t.Fatal(err)
	}

	crlBytes, err := generateCRL(cli.Config{CAFile: testCaFile, CAKeyFile: testCaKeyFile, DBConfigFile: "../testdata/db-config.json", CRLExpiration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}

	verifyCRL(t, crlBytes, "1", 7*helpers.OneDay+time.Second, big.NewInt(0))
}

func TestRevokeExpiry(t *testing.T) {
	err := prepDB()
	if err != nil {
		t.Fatal(err)
	}

	crlBytes, err := generateCRL(cli.Config{CAFile: testCaFile, CAKeyFile: testCaKeyFile, DBConfigFile: "../testdata/db-config.json", CRLExpiration: 23 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}

	verifyCRL(t, crlBytes, "1", 23*time.Hour+time.Second, big.NewInt(0))
}

func TestRevokeNumber(t *testing.T) {
	err := prepDB()
	if err != nil {
		t.Fatal(err)
	}

	crlBytes, err := generateCRL(cli.Config{CAFile: testCaFile, CAKeyFile: testCaKeyFile, DBConfigFile: "../testdata/db-config.json", CRLExpiration: time.Minute, CRLNumber: 1})
	if err != nil {
		t.Fatal(err)
	}

	verifyCRL(t, crlBytes, "1", 23*time.Hour+time.Second, big.NewInt(1))
}
