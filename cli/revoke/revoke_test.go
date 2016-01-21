package revoke

import (
	"testing"
	"time"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/certdb/sql"
	"github.com/cloudflare/cfssl/certdb/testdb"
	"github.com/cloudflare/cfssl/cli"
	"golang.org/x/crypto/ocsp"
)

var dbAccessor certdb.Accessor

func prepDB() (err error) {
	db := testdb.SQLiteDB("../../certdb/testdb/certstore_development.db")
	expirationTime := time.Now().AddDate(1, 0, 0)
	var cert = &certdb.CertificateRecord{
		Serial: "1",
		Expiry: expirationTime,
		PEM:    "unexpired cert",
	}

	dbAccessor = sql.NewAccessor(db)
	err = dbAccessor.InsertCertificate(cert)
	if err != nil {
		return err
	}

	return
}

func TestRevokeMain(t *testing.T) {
	err := prepDB()
	if err != nil {
		t.Fatal(err)
	}

	err = revokeMain([]string{}, cli.Config{Serial: "1", DBConfigFile: "../testdata/db-config.json"})
	if err != nil {
		t.Fatal(err)
	}

	crs, err := dbAccessor.GetCertificate("1")
	if err != nil {
		t.Fatal("Failed to get certificate")
	}

	if crs.Status != "revoked" {
		t.Fatal("Certificate not marked revoked after we revoked it")
	}

	err = revokeMain([]string{}, cli.Config{Serial: "1", Reason: "2", DBConfigFile: "../testdata/db-config.json"})
	if err != nil {
		t.Fatal(err)
	}

	crs, err = dbAccessor.GetCertificate("1")
	if err != nil {
		t.Fatal("Failed to get certificate")
	}

	if crs.Reason != 2 {
		t.Fatal("Certificate revocation reason incorrect")
	}

	err = revokeMain([]string{}, cli.Config{Serial: "1", Reason: "Superseded", DBConfigFile: "../testdata/db-config.json"})
	if err != nil {
		t.Fatal(err)
	}

	crs, err = dbAccessor.GetCertificate("1")
	if err != nil {
		t.Fatal("Failed to get certificate")
	}

	if crs.Reason != ocsp.Superseded {
		t.Fatal("Certificate revocation reason incorrect")
	}

	err = revokeMain([]string{}, cli.Config{Serial: "1", Reason: "invalid_reason", DBConfigFile: "../testdata/db-config.json"})
	if err == nil {
		t.Fatal("Expected error from invalid reason")
	}

	err = revokeMain([]string{}, cli.Config{Serial: "1", Reason: "999", DBConfigFile: "../testdata/db-config.json"})
	if err == nil {
		t.Fatal("Expected error from invalid reason")
	}

	err = revokeMain([]string{}, cli.Config{Serial: "2", DBConfigFile: "../testdata/db-config.json"})
	if err == nil {
		t.Fatal("Expected error from unrecognized serial number")
	}

	err = revokeMain([]string{}, cli.Config{DBConfigFile: "../testdata/db-config.json"})
	if err == nil {
		t.Fatal("Expected error from missing serial number")
	}

	err = revokeMain([]string{}, cli.Config{Serial: "1"})
	if err == nil {
		t.Fatal("Expected error from missing db config")
	}
}
