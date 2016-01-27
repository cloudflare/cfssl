package testdb

import (
	"database/sql"
	"os"

	_ "github.com/lib/pq"           // register postgresql driver
	_ "github.com/mattn/go-sqlite3" // register sqlite3 driver
)

const (
	pgTruncateTables = `
CREATE OR REPLACE FUNCTION truncate_tables() RETURNS void AS $$
DECLARE
    statements CURSOR FOR
        SELECT tablename FROM pg_tables
        WHERE tablename != 'goose_db_version'
          AND tableowner = session_user
          AND schemaname = 'public';
BEGIN
    FOR stmt IN statements LOOP
        EXECUTE 'TRUNCATE TABLE ' || quote_ident(stmt.tablename) || ' CASCADE;';
    END LOOP;
END;
$$ LANGUAGE plpgsql;

SELECT truncate_tables();
`

	sqliteTruncateTables = `
DELETE FROM certificates;
DELETE FROM ocsp_responses;
`
)

// PostgreSQLDB returns a PostgreSQL db instance for certdb testing.
func PostgreSQLDB() *sql.DB {
	connStr := "dbname=certdb_development sslmode=disable"

	if dbURL := os.Getenv("DATABASE_URL"); dbURL != "" {
		connStr = dbURL
	}

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		panic(err)
	}

	if _, err := db.Exec(pgTruncateTables); err != nil {
		panic(err)
	}

	return db
}

// SQLiteDB returns a SQLite db instance for certdb testing.
func SQLiteDB(dbpath string) *sql.DB {
	db, err := sql.Open("sqlite3", dbpath)
	if err != nil {
		panic(err)
	}

	if _, err := db.Exec(sqliteTruncateTables); err != nil {
		panic(err)
	}

	return db
}
