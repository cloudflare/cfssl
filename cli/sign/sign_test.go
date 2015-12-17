package sign

import (
	"testing"

	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/certdb/testdb"
)

func TestSignFromConfig(t *testing.T) {
	_, err := SignerFromConfig(cli.Config{CAFile: "../../testdata/server.crt",
		CAKeyFile: "../../testdata/server.key", Hostname: "www.cloudflare.com", Remote: "127.0.0.1:8888"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignerMain(t *testing.T) {
	err := signerMain([]string{"../../testdata/server.csr"}, cli.Config{CAFile: "../../testdata/server.crt",
		CAKeyFile: "../../testdata/server.key", Hostname: "www.cloudflare.com"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestBadSigner(t *testing.T) {
	err := signerMain([]string{"../../testdata/server.csr"}, cli.Config{CAFile: "", CAKeyFile: ""})
	if err != nil {
		t.Fatal(err)
	}
	err = signerMain([]string{"../../testdata/server.csr"},
		cli.Config{CAFile: "../../testdata/server.crt", CAKeyFile: ""})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignerWithDB(t *testing.T) {
	db := testdb.SQLiteDB("../../certdb/testdb/certstore_development.db")
	err := signerMain([]string{"../../testdata/server.csr"},
		cli.Config{
			CAFile: "../../testdata/server.crt",
			CAKeyFile: "../../testdata/server.key",
			Hostname: "www.cloudflare.com",
			DBConfigFile:"../testdata/db-config.json"})
	if err != nil {
		t.Fatal(err)
	}

	var crs []*certdb.CertificateRecord
	crs, err = certdb.GetUnexpiredCertificates(db)
	if err != nil {
		t.Fatal("Failed to get unexpired certificates")
	}

	if len(crs) != 1 {
		t.Fatal("Expected 1 unexpired certificate in the database after signing 1")
	}
}
