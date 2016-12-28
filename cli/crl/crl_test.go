package crl

import (
	"crypto/x509"
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

func verifyCRL(t *testing.T, crlBytesDER []byte, serial string, expireAfter time.Duration) {
	parsedCrl, err := x509.ParseCRL(crlBytesDER)
	if err != nil {
		t.Fatal("failed to get certificate ", err)
	}
	if !parsedCrl.HasExpired(time.Now().Add(expireAfter)) {
		t.Fatal("the CRL should have expired")
	}
	certs := parsedCrl.TBSCertList.RevokedCertificates
	if len(certs) != 1 {
		t.Fatal("failed to get one certificate")
	}

	cert := certs[0]

	if cert.SerialNumber.String() != serial {
		t.Fatal("cert was not correctly inserted in CRL, serial was " + cert.SerialNumber.String())
	}
}

func TestRevokeMain(t *testing.T) {
	err := prepDB()
	if err != nil {
		t.Fatal(err)
	}

	crlBytes, err := generateCRL(cli.Config{CAFile: testCaFile, CAKeyFile: testCaKeyFile, DBConfigFile: "../testdata/db-config.json"})
	if err != nil {
		t.Fatal(err)
	}

	verifyCRL(t, crlBytes, "1", 7*helpers.OneDay+time.Second)
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

	verifyCRL(t, crlBytes, "1", 23*time.Hour+time.Second)
}
