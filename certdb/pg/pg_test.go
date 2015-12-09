// +build postgresql

package pg

import (
	"math"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/certdb/testdb"
)

var (
	db = testdb.PostgreSQLDB()
)

// roughlySameTime decides if t1 and t2 are close enough.
func roughlySameTime(t1, t2 time.Time) bool {
	// return true if the difference is smaller than 1 sec.
	return math.Abs(float64(t1.Sub(t2))) < float64(time.Second)
}

func TestInsertCertificateAndGetCertificate(t *testing.T) {
	expiry := time.Date(2010, time.December, 25, 23, 0, 0, 0, time.UTC)
	want := &certdb.CertificateRecord{
		PEM:     "fake cert data",
		Serial:  "fake serial",
		CALabel: "default",
		Status:  "good",
		Reason:  0,
		Expiry:  expiry,
	}

	if err := InsertCertificate(db, want); err != nil {
		t.Fatal(err)
	}

	got, err := GetCertificate(db, want.Serial)
	if err != nil {
		t.Fatal(err)
	}

	// relfection comparison with zero time objects are not stable as it seems
	if want.Serial != got.Serial || want.Status != got.Status ||
		want.CALabel != got.CALabel || !got.RevokedAt.IsZero() ||
		want.PEM != got.PEM || !roughlySameTime(got.Expiry, expiry) {
		t.Errorf("want Certificate %+v, got %+v", *want, *got)
	}

	unexpired, err := GetUnexpiredCertificates(db)

	if err != nil {
		t.Fatal(err)
	}

	if len(unexpired) != 0 {
		t.Error("should not have unexpired certificate record")
	}
}

func TestInsertCertificateAndGetUnexpiredCertificate(t *testing.T) {
	expiry := time.Now().Add(time.Minute)
	want := &certdb.CertificateRecord{
		PEM:     "fake cert data",
		Serial:  "fake serial 2",
		CALabel: "default",
		Status:  "good",
		Reason:  0,
		Expiry:  expiry,
	}

	if err := InsertCertificate(db, want); err != nil {
		t.Fatal(err)
	}

	got, err := GetCertificate(db, want.Serial)
	if err != nil {
		t.Fatal(err)
	}

	// relfection comparison with zero time objects are not stable as it seems
	if want.Serial != got.Serial || want.Status != got.Status ||
		want.CALabel != got.CALabel || !got.RevokedAt.IsZero() ||
		want.PEM != got.PEM || !roughlySameTime(got.Expiry, expiry) {
		t.Errorf("want Certificate %+v, got %+v", *want, *got)
	}

	unexpired, err := GetUnexpiredCertificates(db)

	if err != nil {
		t.Fatal(err)
	}

	if len(unexpired) != 1 {
		t.Error("should not have other than 1 unexpired certificate record:", len(unexpired))
	}
}

func TestUpdateCertificateAndGetCertificate(t *testing.T) {
	expiry := time.Date(2010, time.December, 25, 23, 0, 0, 0, time.UTC)
	want := &certdb.CertificateRecord{
		PEM:     "fake cert data",
		Serial:  "fake serial 3",
		CALabel: "default",
		Status:  "good",
		Reason:  0,
		Expiry:  expiry,
	}

	if err := InsertCertificate(db, want); err != nil {
		t.Fatal(err)
	}

	// reason 2 is CACompromise
	if err := RevokeCertificate(db, want.Serial, 2); err != nil {
		t.Fatal(err)
	}

	got, err := GetCertificate(db, want.Serial)
	if err != nil {
		t.Fatal(err)
	}

	// relfection comparison with zero time objects are not stable as it seems
	if want.Serial != got.Serial || got.Status != "revoked" ||
		want.CALabel != got.CALabel || got.RevokedAt.IsZero() ||
		want.PEM != got.PEM {
		t.Errorf("want Certificate %+v, got %+v", *want, *got)
	}
}

func TestInsertOCSPAndGetOCSP(t *testing.T) {
	expiry := time.Date(2010, time.December, 25, 23, 0, 0, 0, time.UTC)
	want := &certdb.OCSPRecord{
		Serial: "fake serial",
		Body:   "fake body",
		Expiry: expiry,
	}

	if err := InsertOCSP(db, want); err != nil {
		t.Fatal(err)
	}

	got, err := GetOCSP(db, want.Serial)
	if err != nil {
		t.Fatal(err)
	}

	if want.Serial != got.Serial || want.Body != got.Body ||
		!roughlySameTime(want.Expiry, got.Expiry) {
		t.Errorf("want OCSP %+v, got %+v", *want, *got)
	}

	unexpired, err := GetUnexpiredOCSPs(db)

	if err != nil {
		t.Fatal(err)
	}

	if len(unexpired) != 0 {
		t.Error("should not have unexpired certificate record")
	}
}

func TestInsertOCSPAndGetUnexpiredOCSP(t *testing.T) {
	want := &certdb.OCSPRecord{
		Serial: "fake serial 2",
		Body:   "fake body",
		Expiry: time.Now().Add(time.Minute),
	}

	if err := InsertOCSP(db, want); err != nil {
		t.Fatal(err)
	}

	got, err := GetOCSP(db, want.Serial)
	if err != nil {
		t.Fatal(err)
	}

	if want.Serial != got.Serial || want.Body != got.Body ||
		!roughlySameTime(want.Expiry, got.Expiry) {
		t.Errorf("want OCSP %+v, got %+v", *want, *got)
	}

	unexpired, err := GetUnexpiredOCSPs(db)

	if err != nil {
		t.Fatal(err)
	}

	if len(unexpired) != 1 {
		t.Error("should not have other than 1 unexpired certificate record:", len(unexpired))
	}
}

func TestUpdateOCSPAndGetOCSP(t *testing.T) {
	want := &certdb.OCSPRecord{
		Serial: "fake serial 3",
		Body:   "fake body",
		Expiry: time.Date(2010, time.December, 25, 23, 0, 0, 0, time.UTC),
	}

	if err := InsertOCSP(db, want); err != nil {
		t.Fatal(err)
	}

	newExpiry := time.Now().Add(time.Hour)
	if err := UpdateOCSP(db, want.Serial, "fake body revoked", newExpiry); err != nil {
		t.Fatal(err)
	}

	got, err := GetOCSP(db, want.Serial)
	if err != nil {
		t.Fatal(err)
	}

	want.Expiry = newExpiry
	if want.Serial != got.Serial || got.Body != "fake body revoked" ||
		!roughlySameTime(newExpiry, got.Expiry) {
		t.Errorf("want OCSP %+v, got %+v", *want, *got)
	}
}
