package certstore

import (
	"time"

	"crypto/x509"
	"database/sql"

	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/log"
	_ "github.com/mattn/go-sqlite3" // Initialize SQLite without bringing it in scope
)

// Certificate represents a certificate in the certstore
type Certificate struct {
	AsPEM            string
	Serial           string
	SignedAt         time.Time
	Expiration       time.Time
	RevokedAt        *time.Time
	RevocationReason sql.NullInt64
}

var certificatesSchema = `
	CREATE TABLE IF NOT EXISTS certificates (
		asPEM VARCHAR(10000),
		serial VARCHAR(50) PRIMARY KEY,
		signedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		expiration TIMESTAMP,
		revokedAt TIMESTAMP NULL DEFAULT NULL,
		revocationReason INTEGER NULL DEFAULT NULL
	);
`

func initializeDB() (db *sql.DB, err error) {
	db, err = sql.Open("sqlite3", "./certstore.db")

	if err != nil {
		return nil, cferr.New(cferr.CertStoreError, cferr.DatabaseInitializationFailed)
	}

	_, err = db.Exec(certificatesSchema)
	return db, err
}

// RecordCert records a new signed cert in the certificate store
func RecordCert(cert x509.Certificate, signedCert []byte) (err error) {
	db, err := initializeDB()

	if err != nil {
		return
	}

	_, err = db.Exec("INSERT INTO certificates (serial, asPEM, expiration) VALUES ($1, $2, $3)",
		cert.SerialNumber.String(), signedCert, cert.NotAfter)

	if err != nil {
		return cferr.New(cferr.CertStoreError, cferr.RecordCertFailed)
	}

	return
}

// RevokeCert revokes a cert with a given serial number and reason code
func RevokeCert(id string, reasonCode int) (err error) {
	var db *sql.DB
	db, err = initializeDB()

	if err != nil {
		return
	}

	var result sql.Result
	result, err = db.Exec("UPDATE certificates SET revokedAt=DATETIME(), revocationReason=$1 WHERE serial = $2",
		reasonCode, id)

	if err != nil {
		return cferr.New(cferr.CertStoreError, cferr.RevokeCertFailed)
	}

	var numRowsAffected int64
	numRowsAffected, err = result.RowsAffected()

	if numRowsAffected != 1 {
		return cferr.New(cferr.CertStoreError, cferr.NoMatchingCert)
	}

	return
}

// GetUnexpiredCerts returns all certs in the store which have not expired
// and information about revocation if applicable
func GetUnexpiredCerts() (certs []Certificate, err error) {
	var db *sql.DB
	db, err = initializeDB()

	if err != nil {
		return nil, err
	}

	var rows *sql.Rows
	rows, err = db.Query("SELECT * FROM certificates WHERE DATETIME() < expiration")

	if err != nil {
		return nil, cferr.New(cferr.CertStoreError, cferr.GetUnexpiredCertsFailed)
	}

	for rows.Next() {
		var cert Certificate
		err = rows.Scan(&cert.AsPEM, &cert.Serial, &cert.SignedAt, &cert.Expiration, &cert.RevokedAt, &cert.RevocationReason)
		if err != nil {
			log.Error(err)
			return nil, cferr.New(cferr.CertStoreError, cferr.GetUnexpiredCertsFailed)
		}
		certs = append(certs, cert)
	}
	rows.Close()

	return certs, err
}
