package pg

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/cloudflare/cfssl/certdb"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/kisielk/sqlstruct"
)

const (
	insertSQL = `
INSERT INTO certificates (serial, ca_label, status, reason, expiry, revoked_at, pem)
	VALUES ($1, $2, $3, $4, $5, $6, $7);`

	selectSQL = `
SELECT %s FROM certificates
	WHERE (serial = $1);`

	selectAllSQL = `
SELECT %s FROM certificates;`

	selectAllUnexpiredSQL = `
SELECT %s FROM certificates
WHERE current_timestamp < expiry;`

	updateRevokeSQL = `
UPDATE certificates
	SET status='revoked', revoked_at=current_timestamp, reason=$1
	WHERE (serial = $2)`

	insertOCSPSQL = `
INSERT INTO ocsp_responses (serial, body, expiry)
    VALUES ($1, $2, $3);`

	updateOCSPSQL = `
UPDATE ocsp_responses
    SET expiry=$3, body=$2
	WHERE (serial = $1);`

	selectAllUnexpiredOCSPSQL = `
SELECT %s FROM ocsp_responses
WHERE current_timestamp < expiry;`

	selectOCSPSQL = `
SELECT %s FROM ocsp_responses
    WHERE (serial = $1);`
)

func wrapCertStoreError(err error) error {
	if err != nil {
		return cferr.Wrap(cferr.CertStoreError, cferr.Unknown, err)
	}
	return nil
}

// InsertCertificate puts a certdb.CertificateRecord into db.
func InsertCertificate(db *sql.DB, cr *certdb.CertificateRecord) error {
	res, err := db.Exec(
		insertSQL,
		cr.Serial,
		cr.CALabel,
		cr.Status,
		cr.Reason,
		cr.Expiry,
		cr.RevokedAt,
		cr.PEM,
	)
	if err != nil {
		return wrapCertStoreError(err)
	}

	numRowsAffected, _ := res.RowsAffected()

	if numRowsAffected != 1 {
		return wrapCertStoreError(fmt.Errorf("%d rows are affected, should be 1 row", numRowsAffected))
	}

	return nil
}

// GetCertificate gets a certdb.CertificateRecord indexed by serial.
func GetCertificate(db *sql.DB, serial string) (*certdb.CertificateRecord, error) {
	cr := new(certdb.CertificateRecord)
	rows, err := db.Query(fmt.Sprintf(selectSQL, sqlstruct.Columns(*cr)), serial)
	if err != nil {
		return nil, wrapCertStoreError(err)
	}
	defer rows.Close()

	if rows.Next() {
		return cr, wrapCertStoreError(sqlstruct.Scan(cr, rows))
	}
	return nil, nil
}

// GetUnexpiredCertificates gets all unexpired certificate from db.
func GetUnexpiredCertificates(db *sql.DB) (crs []*certdb.CertificateRecord, err error) {
	cr := new(certdb.CertificateRecord)
	rows, err := db.Query(fmt.Sprintf(selectAllUnexpiredSQL, sqlstruct.Columns(*cr)))
	if err != nil {
		return nil, wrapCertStoreError(err)
	}
	defer rows.Close()

	for rows.Next() {
		err = sqlstruct.Scan(cr, rows)
		if err != nil {
			return nil, wrapCertStoreError(err)
		}
		crs = append(crs, cr)
	}

	return crs, nil
}

// RevokeCertificate updates a certificate with a given serial number and marks it revoked.
func RevokeCertificate(db *sql.DB, serial string, reasonCode int) error {
	result, err := db.Exec(updateRevokeSQL, reasonCode, serial)

	if err != nil {
		return wrapCertStoreError(err)
	}

	numRowsAffected, _ := result.RowsAffected()

	if numRowsAffected != 1 {
		return wrapCertStoreError(fmt.Errorf("%d rows are affected, should be 1 row", numRowsAffected))
	}

	return nil
}

// InsertOCSP puts a new OCSPRecord into the db.
func InsertOCSP(db *sql.DB, rr *certdb.OCSPRecord) error {
	res, err := db.Exec(
		insertOCSPSQL,
		rr.Serial,
		rr.Body,
		rr.Expiry,
	)
	if err != nil {
		return wrapCertStoreError(err)
	}

	numRowsAffected, _ := res.RowsAffected()

	if numRowsAffected != 1 {
		return wrapCertStoreError(fmt.Errorf("%d rows are affected, should be 1 row", numRowsAffected))
	}

	return nil
}

// GetOCSP retrieves a OCSPRecord from db by serial.
func GetOCSP(db *sql.DB, serial string) (rr *certdb.OCSPRecord, err error) {
	rr = new(certdb.OCSPRecord)
	rows, err := db.Query(fmt.Sprintf(selectOCSPSQL, sqlstruct.Columns(*rr)), serial)
	if err != nil {
		return nil, wrapCertStoreError(err)
	}
	defer rows.Close()

	if rows.Next() {
		return rr, sqlstruct.Scan(rr, rows)
	}
	return nil, nil
}

// GetUnexpiredOCSPs retrieves all unexpired OCSPRecord from db.
func GetUnexpiredOCSPs(db *sql.DB) (rrs []*certdb.OCSPRecord, err error) {
	rr := new(certdb.OCSPRecord)
	rows, err := db.Query(fmt.Sprintf(selectAllUnexpiredOCSPSQL, sqlstruct.Columns(*rr)))
	if err != nil {
		return nil, wrapCertStoreError(err)
	}
	defer rows.Close()

	for rows.Next() {
		err = sqlstruct.Scan(rr, rows)
		if err != nil {
			return nil, wrapCertStoreError(err)
		}
		rrs = append(rrs, rr)
	}

	return rrs, nil
}

// UpdateOCSP updates a ocsp response record with a given serial number.
func UpdateOCSP(db *sql.DB, serial, body string, expiry time.Time) (err error) {
	var result sql.Result
	result, err = db.Exec(updateOCSPSQL, serial, body, expiry)

	if err != nil {
		return wrapCertStoreError(err)
	}

	var numRowsAffected int64
	numRowsAffected, err = result.RowsAffected()

	if numRowsAffected != 1 {
		return wrapCertStoreError(fmt.Errorf("%d rows are affected, should be 1 row", numRowsAffected))
	}
	return
}
