// +build postgresql

package sql

import (
	"testing"

	"github.com/cloudflare/cfssl/certdb/testdb"
)

func TestPostgreSQL(t *testing.T) {
	db := testdb.PostgreSQLDB()
	dba := NewAccessor(db)
	testEverything(dba, t)
}
