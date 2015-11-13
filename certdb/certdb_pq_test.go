// +build postgresql

package certdb

import (
	"testing"

	"github.com/cloudflare/cfssl/certdb/testdb"
)

func TestPostgreSQL(t *testing.T) {
	db := testdb.PostgreSQLDB()
	testInsertCertificateAndGetCertificate(db, t)
	testInsertCertificateAndGetUnexpiredCertificate(db, t)
	testUpdateCertificateAndGetCertificate(db, t)
	testInsertOCSPAndGetOCSP(db, t)
	testInsertOCSPAndGetUnexpiredOCSP(db, t)
	testUpdateOCSPAndGetOCSP(db, t)
}
