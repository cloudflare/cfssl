package certdb

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/kisielk/sqlstruct"
)

type CertificateRecord struct {
	Serial    string     `sql:"serial"`
	CALabel   string     `sql:"ca_label"`
	Status    string     `sql:"status"`
	Reason    int        `sql:"reason"`
	RevokedAt *time.Time `sql:"revoked_at"`
	PEM       string     `sql:"pem"`
}

const (
	insertSQL = `
INSERT INTO certificates (serial, ca_label, status, reason, revoked_at, pem)
	VALUES ($1, $2, $3, $4, $5, $6)
	RETURNING serial;`

	selectSQL = `
SELECT %s FROM certificates
	WHERE (serial = $1);`

	selectAllSQL = `
SELECT %s FROM certificates`
)

func (cr *CertificateRecord) Insert(db *sql.DB) error {
	return db.QueryRow(insertSQL, cr.Serial, cr.CALabel, cr.Status, cr.Reason, cr.RevokedAt, cr.PEM).Scan(&cr.Serial)
}

func GetCertificateRecord(db *sql.DB, serial string) (cr *CertificateRecord, err error) {
	cr = new(CertificateRecord)
	rows, err := db.Query(fmt.Sprintf(selectSQL, sqlstruct.Columns(*cr)), serial)
	defer rows.Close()
	if err != nil {
		return nil, err
	}

	if rows.Next() {
		return cr, sqlstruct.Scan(cr, rows)
	}
	return nil, nil
}

func GetUnexpiredCertificateRecord(db *sql.DB) (crs []*CertificateRecord, err error) {
	var cr *CertificateRecord
	rows, err := db.Query(fmt.Sprintf(selectAllSQL, sqlstruct.Columns(*cr)))
	defer rows.Close()
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		err = sqlstruct.Scan(cr, rows)
		if err != nil {
			return nil, err
		}
		crs = append(crs, cr)
	}

	return crs, nil
}
