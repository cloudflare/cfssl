package certdb

import (
	"database/sql"
	"fmt"
	"time"

	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/kisielk/sqlstruct"
)

// CertificateRecord represents a certificate record in the cert db
type CertificateRecord struct {
	Serial    string     `sql:"serial"`
	CALabel   string     `sql:"ca_label"`
	Status    string     `sql:"status"`
	Reason    int        `sql:"reason"`
	ExpiresAt *time.Time `sql:"expires_at"`
	RevokedAt *time.Time `sql:"revoked_at"`
	PEM       string     `sql:"pem"`
}

const (
	insertSQL = `
INSERT INTO certificates (serial, ca_label, status, reason, expires_at, revoked_at, pem)
	VALUES ($1, $2, $3, $4, $5, $6, $7);`

	selectSQL = `
SELECT %s FROM certificates
	WHERE (serial = $1);`

	selectAllSQL = `
SELECT %s FROM certificates`

	selectAllUnexpiredSQL = `
SELECT %s FROM certificates
	WHERE DATETIME() < expires_at`

	updateRevokeSQL = `
UPDATE certificates
	SET revoked_at=DATETIME(), reason=$1, status='revoked'
	WHERE serial=$2
	`
)

// InsertCertificate inserts a certificate record into the database
func InsertCertificate(db *sql.DB, cr *CertificateRecord) (err error) {
	_, err = db.Exec(insertSQL, cr.Serial, cr.CALabel, cr.Status, cr.Reason, cr.ExpiresAt, cr.RevokedAt, cr.PEM)
	if err != nil {
		return cferr.Wrap(cferr.CertStoreError, cferr.RecordCertFailed, err)
	}
	return
}

// GetCertificateRecord retrieves a certificate record from the database
func GetCertificateRecord(db *sql.DB, serial string) (cr *CertificateRecord, err error) {
	cr = new(CertificateRecord)
	rows, err := db.Query(fmt.Sprintf(selectSQL, sqlstruct.Columns(*cr)), serial)
	defer rows.Close()
	if err != nil {
		return nil, cferr.Wrap(cferr.CertStoreError, cferr.GetCertificateRecordFailed, err)
	}

	if rows.Next() {
		return cr, sqlstruct.Scan(cr, rows)
	}
	return nil, nil
}

// GetUnexpiredCertificateRecords fetches all certificates in the database which have not expired
func GetUnexpiredCertificateRecords(db *sql.DB) (crs []*CertificateRecord, err error) {
	cr := new(CertificateRecord)
	rows, err := db.Query(fmt.Sprintf(selectAllUnexpiredSQL, sqlstruct.Columns(*cr)))
	defer rows.Close()
	if err != nil {
		return nil, cferr.Wrap(cferr.CertStoreError, cferr.GetUnexpiredCertsFailed, err)
	}

	for rows.Next() {
		err = sqlstruct.Scan(cr, rows)
		if err != nil {
			return nil, cferr.Wrap(cferr.CertStoreError, cferr.GetUnexpiredCertsFailed, err)
		}
		crs = append(crs, cr)
	}

	return crs, nil
}

// RevokeCertificate updates a certificate with a given serial number and marks it revoked
func RevokeCertificate(db *sql.DB, serial string, reasonCode int) (err error) {
	var result sql.Result
	result, err = db.Exec(updateRevokeSQL, reasonCode, serial)

	if err != nil {
		return cferr.Wrap(cferr.CertStoreError, cferr.RevokeCertFailed, err)
	}

	var numRowsAffected int64
	numRowsAffected, err = result.RowsAffected()

	if numRowsAffected != 1 {
		return cferr.New(cferr.CertStoreError, cferr.NoMatchingCert)
	}
	return
}