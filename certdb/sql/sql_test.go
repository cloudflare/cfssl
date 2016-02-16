package sql

import (
	"math"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/certdb/testdb"
)

const (
	sqliteDBFile = "../testdb/certstore_development.db"
	fakeAKI      = "fake_aki"
)

func TestNoDB(t *testing.T) {
	dba := &Accessor{}
	_, err := dba.GetCertificate("foobar serial", "random aki")
	if err == nil {
		t.Fatal("should return error")
	}
}

func TestSQLite(t *testing.T) {
	db := testdb.SQLiteDB(sqliteDBFile)
	dba := NewAccessor(db)
	testEverything(dba, t)
}

// roughlySameTime decides if t1 and t2 are close enough.
func roughlySameTime(t1, t2 time.Time) bool {
	// return true if the difference is smaller than 1 sec.
	return math.Abs(float64(t1.Sub(t2))) < float64(time.Second)
}

func testEverything(dba certdb.Accessor, t *testing.T) {
	testInsertCertificateAndGetCertificate(dba, t)
	testInsertCertificateAndGetUnexpiredCertificate(dba, t)
	testUpdateCertificateAndGetCertificate(dba, t)
	testInsertOCSPAndGetOCSP(dba, t)
	testInsertOCSPAndGetUnexpiredOCSP(dba, t)
	testUpdateOCSPAndGetOCSP(dba, t)
	testUpsertOCSPAndGetOCSP(dba, t)
}

func testInsertCertificateAndGetCertificate(dba certdb.Accessor, t *testing.T) {
	expiry := time.Date(2010, time.December, 25, 23, 0, 0, 0, time.UTC)
	want := certdb.CertificateRecord{
		PEM:    "fake cert data",
		Serial: "fake serial",
		AKI:    fakeAKI,
		Status: "good",
		Reason: 0,
		Expiry: expiry,
	}

	if err := dba.InsertCertificate(want); err != nil {
		t.Fatal(err)
	}

	rets, err := dba.GetCertificate(want.Serial, want.AKI)
	if err != nil {
		t.Fatal(err)
	}

	if len(rets) != 1 {
		t.Fatal("should only return one record.")
	}

	got := rets[0]

	// relfection comparison with zero time objects are not stable as it seems
	if want.Serial != got.Serial || want.Status != got.Status ||
		want.AKI != got.AKI || !got.RevokedAt.IsZero() ||
		want.PEM != got.PEM || !roughlySameTime(got.Expiry, expiry) {
		t.Errorf("want Certificate %+v, got %+v", want, got)
	}

	unexpired, err := dba.GetUnexpiredCertificates()

	if err != nil {
		t.Fatal(err)
	}

	if len(unexpired) != 0 {
		t.Error("should not have unexpired certificate record")
	}
}

func testInsertCertificateAndGetUnexpiredCertificate(dba certdb.Accessor, t *testing.T) {
	expiry := time.Now().Add(time.Minute)
	want := certdb.CertificateRecord{
		PEM:    "fake cert data",
		Serial: "fake serial 2",
		AKI:    fakeAKI,
		Status: "good",
		Reason: 0,
		Expiry: expiry,
	}

	if err := dba.InsertCertificate(want); err != nil {
		t.Fatal(err)
	}

	rets, err := dba.GetCertificate(want.Serial, want.AKI)
	if err != nil {
		t.Fatal(err)
	}

	if len(rets) != 1 {
		t.Fatal("should return exactly one record")
	}

	got := rets[0]

	// relfection comparison with zero time objects are not stable as it seems
	if want.Serial != got.Serial || want.Status != got.Status ||
		want.AKI != got.AKI || !got.RevokedAt.IsZero() ||
		want.PEM != got.PEM || !roughlySameTime(got.Expiry, expiry) {
		t.Errorf("want Certificate %+v, got %+v", want, got)
	}

	unexpired, err := dba.GetUnexpiredCertificates()

	if err != nil {
		t.Fatal(err)
	}

	if len(unexpired) != 1 {
		t.Error("should not have other than 1 unexpired certificate record:", len(unexpired))
	}
}

func testUpdateCertificateAndGetCertificate(dba certdb.Accessor, t *testing.T) {
	expiry := time.Date(2010, time.December, 25, 23, 0, 0, 0, time.UTC)
	want := certdb.CertificateRecord{
		PEM:    "fake cert data",
		Serial: "fake serial 3",
		AKI:    fakeAKI,
		Status: "good",
		Reason: 0,
		Expiry: expiry,
	}

	if err := dba.InsertCertificate(want); err != nil {
		t.Fatal(err)
	}

	// reason 2 is CACompromise
	if err := dba.RevokeCertificate(want.Serial, want.AKI, 2); err != nil {
		t.Fatal(err)
	}

	rets, err := dba.GetCertificate(want.Serial, want.AKI)
	if err != nil {
		t.Fatal(err)
	}

	if len(rets) != 1 {
		t.Fatal("should return exactly one record")
	}

	got := rets[0]

	// relfection comparison with zero time objects are not stable as it seems
	if want.Serial != got.Serial || got.Status != "revoked" ||
		want.AKI != got.AKI || got.RevokedAt.IsZero() ||
		want.PEM != got.PEM {
		t.Errorf("want Certificate %+v, got %+v", want, got)
	}
}

func testInsertOCSPAndGetOCSP(dba certdb.Accessor, t *testing.T) {
	expiry := time.Date(2010, time.December, 25, 23, 0, 0, 0, time.UTC)
	want := certdb.OCSPRecord{
		Serial: "fake serial",
		AKI:    fakeAKI,
		Body:   "fake body",
		Expiry: expiry,
	}

	if err := dba.InsertOCSP(want); err != nil {
		t.Fatal(err)
	}

	rets, err := dba.GetOCSP(want.Serial, want.AKI)
	if err != nil {
		t.Fatal(err)
	}
	if len(rets) != 1 {
		t.Fatal("should return exactly one record")
	}

	got := rets[0]

	if want.Serial != got.Serial || want.Body != got.Body ||
		!roughlySameTime(want.Expiry, got.Expiry) {
		t.Errorf("want OCSP %+v, got %+v", want, got)
	}

	unexpired, err := dba.GetUnexpiredOCSPs()

	if err != nil {
		t.Fatal(err)
	}

	if len(unexpired) != 0 {
		t.Error("should not have unexpired certificate record")
	}
}

func testInsertOCSPAndGetUnexpiredOCSP(dba certdb.Accessor, t *testing.T) {
	want := certdb.OCSPRecord{
		Serial: "fake serial 2",
		AKI:    fakeAKI,
		Body:   "fake body",
		Expiry: time.Now().Add(time.Minute),
	}

	if err := dba.InsertOCSP(want); err != nil {
		t.Fatal(err)
	}

	rets, err := dba.GetOCSP(want.Serial, want.AKI)
	if err != nil {
		t.Fatal(err)
	}
	if len(rets) != 1 {
		t.Fatal("should return exactly one record")
	}

	got := rets[0]

	if want.Serial != got.Serial || want.Body != got.Body ||
		!roughlySameTime(want.Expiry, got.Expiry) {
		t.Errorf("want OCSP %+v, got %+v", want, got)
	}

	unexpired, err := dba.GetUnexpiredOCSPs()

	if err != nil {
		t.Fatal(err)
	}

	if len(unexpired) != 1 {
		t.Error("should not have other than 1 unexpired certificate record:", len(unexpired))
	}
}

func testUpdateOCSPAndGetOCSP(dba certdb.Accessor, t *testing.T) {
	want := certdb.OCSPRecord{
		Serial: "fake serial 3",
		AKI:    fakeAKI,
		Body:   "fake body",
		Expiry: time.Date(2010, time.December, 25, 23, 0, 0, 0, time.UTC),
	}

	if err := dba.InsertOCSP(want); err != nil {
		t.Fatal(err)
	}

	want.Body = "fake body revoked"
	newExpiry := time.Now().Add(time.Hour)
	if err := dba.UpdateOCSP(want.Serial, want.AKI, want.Body, newExpiry); err != nil {
		t.Fatal(err)
	}

	rets, err := dba.GetOCSP(want.Serial, want.AKI)
	if err != nil {
		t.Fatal(err)
	}
	if len(rets) != 1 {
		t.Fatal("should return exactly one record")
	}

	got := rets[0]

	want.Expiry = newExpiry
	if want.Serial != got.Serial || got.Body != "fake body revoked" ||
		!roughlySameTime(newExpiry, got.Expiry) {
		t.Errorf("want OCSP %+v, got %+v", want, got)
	}
}

func testUpsertOCSPAndGetOCSP(dba certdb.Accessor, t *testing.T) {
	want := certdb.OCSPRecord{
		Serial: "fake serial 3",
		AKI:    fakeAKI,
		Body:   "fake body",
		Expiry: time.Date(2010, time.December, 25, 23, 0, 0, 0, time.UTC),
	}

	if err := dba.UpsertOCSP(want.Serial, want.AKI, want.Body, want.Expiry); err != nil {
		t.Fatal(err)
	}

	rets, err := dba.GetOCSP(want.Serial, want.AKI)
	if err != nil {
		t.Fatal(err)
	}
	if len(rets) != 1 {
		t.Fatal("should return exactly one record")
	}

	got := rets[0]

	if want.Serial != got.Serial || want.Body != got.Body ||
		!roughlySameTime(want.Expiry, got.Expiry) {
		t.Errorf("want OCSP %+v, got %+v", want, got)
	}

	newExpiry := time.Now().Add(time.Hour)
	if err := dba.UpsertOCSP(want.Serial, want.AKI, "fake body revoked", newExpiry); err != nil {
		t.Fatal(err)
	}

	rets, err = dba.GetOCSP(want.Serial, want.AKI)
	if err != nil {
		t.Fatal(err)
	}
	if len(rets) != 1 {
		t.Fatal("should return exactly one record")
	}

	got = rets[0]

	want.Expiry = newExpiry
	if want.Serial != got.Serial || got.Body != "fake body revoked" ||
		!roughlySameTime(newExpiry, got.Expiry) {
		t.Errorf("want OCSP %+v, got %+v", want, got)
	}
}
