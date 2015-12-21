package certdb

import (
	"time"
)

// CertificateRecord encodes a certificate and its metadata
// that will be recorded in a database.
type CertificateRecord struct {
	Serial    string    `sql:"serial_number"`
	AKI       string    `sql:"authority_key_identifier"`
	Status    string    `sql:"status"`
	Reason    int       `sql:"reason"`
	Expiry    time.Time `sql:"expiry"`
	RevokedAt time.Time `sql:"revoked_at"`
	PEM       string    `sql:"pem"`
}

// OCSPRecord encodes a OCSP response body and its metadata
// that will be recorded in a database.
type OCSPRecord struct {
	Serial string    `sql:"serial_number"`
	AKI    string    `sql:"authority_key_identifier"`
	Body   string    `sql:"body"`
	Expiry time.Time `sql:"expiry"`
}

// Accessor abstracts the CRUD of certdb objects from a DB.
type Accessor interface {
	InsertCertificate(cr CertificateRecord) error
	GetCertificate(serial, aki string) ([]CertificateRecord, error)
	GetUnexpiredCertificates() ([]CertificateRecord, error)
	RevokeCertificate(serial, aki string, reasonCode int) error
	InsertOCSP(rr OCSPRecord) error
	GetOCSP(serial, aki string) ([]OCSPRecord, error)
	GetUnexpiredOCSPs() ([]OCSPRecord, error)
	UpdateOCSP(serial, aki, body string, expiry time.Time) error
	UpsertOCSP(serial, aki, body string, expiry time.Time) error
}
