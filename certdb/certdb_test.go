package certdb

import (
	"database/sql"
	"testing"
	"time"

	"bitbucket.org/liamstask/goose/lib/goose"
	_ "github.com/mattn/go-sqlite3"
)

func prepDB() (db *sql.DB, err error) {
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		return nil, err
	}

	var dbconf *goose.DBConf
	dbconf, err = goose.NewDBConf("sqlite/", "test", "")
	if err != nil {
		return nil, err
	}

	err = goose.RunMigrationsOnDb(dbconf, "sqlite/", 1, db)
	if err != nil {
		return nil, err
	}

	expirationTime := time.Now().AddDate(1, 0, 0)
	var cert = &CertificateRecord{
		Serial:    "1",
		CALabel:   "",
		Status:    "",
		Reason:    0,
		ExpiresAt: &expirationTime,
		RevokedAt: nil,
		PEM:       "unexpired cert",
	}

	err = InsertCertificate(db, cert)
	if err != nil {
		return nil, err
	}

	expirationTime = time.Now().AddDate(-1, 0, 0)
	cert.PEM = "expired cert"
	cert.Serial = "2"

	err = InsertCertificate(db, cert)
	if err != nil {
		return nil, err
	}

	return
}

func TestRetrieveCert(t *testing.T) {
	db, err := prepDB()
	if err != nil {
		t.Fatal(err)
	}

	var foundCert *CertificateRecord
	foundCert, err = GetCertificateRecord(db, "1")
	if err != nil {
		t.Fatal(err)
	}

	if foundCert.PEM != "unexpired cert" {
		t.Fatal("cert db returned wrong certificate")
	}

	foundCert, err = GetCertificateRecord(db, "2")
	if err != nil {
		t.Fatal(err)
	}

	if foundCert.PEM != "expired cert" {
		t.Fatal("cert db returned wrong certificate")
	}
}

func TestGetUnexpiredCerts(t *testing.T) {
	db, err := prepDB()
	if err != nil {
		t.Fatal(err)
	}

	var certs []*CertificateRecord
	certs, err = GetUnexpiredCertificateRecords(db)
	if err != nil {
		t.Fatal(err)
	}

	if len(certs) != 1 {
		t.Fatal("cert db returned wrong number of unexpired certificates")
	}

	if certs[0].PEM != "unexpired cert" {
		t.Fatal("cert db returned wrong unexpired certificate")
	}
}

func TestRevokeCert(t *testing.T) {
	db, err := prepDB()
	if err != nil {
		t.Fatal(err)
	}

	var foundCert *CertificateRecord
	foundCert, err = GetCertificateRecord(db, "1")
	if err != nil {
		t.Fatal(err)
	}

	if foundCert.Status != "" {
		t.Fatal("cert db returned cert with unexpected status")
	}

	err = RevokeCertificate(db, "1", 1)
	if err != nil {
		t.Fatal(err)
	}

	foundCert, err = GetCertificateRecord(db, "1")
	if err != nil {
		t.Fatal(err)
	}

	if foundCert.Status != "revoked" {
		t.Fatal("revocation failed")
	}

	if foundCert.Reason != 1 {
		t.Fatal("revocation didn't record reason")
	}
}
