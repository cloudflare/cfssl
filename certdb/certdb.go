package certdb

import (
	"time"
)

// CertificateRecord encodes a certificate and its metadata
// that will be recorded in a database.
type CertificateRecord struct {
	Serial    string    `sql:"serial"`
	CALabel   string    `sql:"ca_label"`
	Status    string    `sql:"status"`
	Reason    int       `sql:"reason"`
	Expiry    time.Time `sql:"expiry"`
	RevokedAt time.Time `sql:"revoked_at"`
	PEM       string    `sql:"pem"`
}

// OCSPRecord encodes a OCSP response body and its metadata
// that will be recorded in a database.
type OCSPRecord struct {
	Serial string    `sql:"serial"`
	Body   string    `sql:"body"`
	Expiry time.Time `sql:"expiry"`
}
