package helpers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"math"
	"testing"
	"time"
)

const (
	testCertFile            = "testdata/cert.pem"
	testBundleFile          = "testdata/bundle.pem"
	testExtraWSCertFile     = "testdata/cert_with_whitespace.pem"
	testExtraWSBundleFile   = "testdata/bundle_with_whitespace.pem"
	testMessedUpBundleFile  = "testdata/messed_up_bundle.pem"
	testMessedUpCertFile    = "testdata/messedupcert.pem"
	testEmptyCertFile       = "testdata/emptycert.pem"
	testPrivateKey          = "testdata/priv_key.pem"
	testMessedUpPrivateKey  = "testdata/messed_up_priv_key.pem"
	testEncryptedPrivateKey = "testdata/enc_priv_key.pem"
	testEmptyPem            = "testdata/empty.pem"
	testNoHeaderCert        = "testdata/noheadercert.pem"
)

func TestKeyLength(t *testing.T) {
	expNil := 0
	recNil := KeyLength(nil)
	if expNil != recNil {
		t.Fatal("KeyLength on nil did not return 0")
	}

	expNonsense := 0
	inNonsense := "string?"
	outNonsense := KeyLength(inNonsense)
	if expNonsense != outNonsense {
		t.Fatal("KeyLength malfunctioning on nonsense input")
	}

	//test the ecdsa branch
	ecdsaPriv, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	ecdsaIn, _ := ecdsaPriv.Public().(*ecdsa.PublicKey)
	expEcdsa := ecdsaIn.Curve.Params().BitSize
	outEcdsa := KeyLength(ecdsaIn)
	if expEcdsa != outEcdsa {
		t.Fatal("KeyLength malfunctioning on ecdsa input")
	}

	//test the rsa branch
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 256)
	rsaIn, _ := rsaPriv.Public().(*rsa.PublicKey)
	expRsa := rsaIn.N.BitLen()
	outRsa := KeyLength(rsaIn)

	if expRsa != outRsa {
		t.Fatal("KeyLength malfunctioning on rsa input")
	}
}

func TestExpiryTime(t *testing.T) {
	// nil case
	var expNil *time.Time
	inNil := []*x509.Certificate{}
	outNil := ExpiryTime(inNil)
	if expNil != outNil {
		t.Fatal("Expiry time is malfunctioning on empty input")
	}

	//read a pem file and use that expiry date
	bytes, _ := ioutil.ReadFile(testBundleFile)
	certs, err := ParseCertificatesPEM(bytes)
	if err != nil {
		t.Fatalf("%v", err)
	}
	expected := time.Date(2014, time.April, 15, 0, 0, 0, 0, time.UTC)
	out := ExpiryTime(certs)
	if out == nil {
		t.Fatal("Expiry time returning null")
	}
	if *out != expected {
		t.Fatalf("Expected %v, got %v", expected, *out)
	}

}

func TestHashAlgoString(t *testing.T) {
	if HashAlgoString(x509.MD2WithRSA) != "MD2" {
		t.Fatal("standin")
	}
	if HashAlgoString(x509.MD5WithRSA) != "MD5" {
		t.Fatal("standin")
	}
	if HashAlgoString(x509.SHA1WithRSA) != "SHA1" {
		t.Fatal("standin")
	}
	if HashAlgoString(x509.SHA256WithRSA) != "SHA256" {
		t.Fatal("standin")
	}
	if HashAlgoString(x509.SHA384WithRSA) != "SHA384" {
		t.Fatal("standin")
	}
	if HashAlgoString(x509.SHA512WithRSA) != "SHA512" {
		t.Fatal("standin")
	}
	if HashAlgoString(x509.DSAWithSHA1) != "SHA1" {
		t.Fatal("standin")
	}
	if HashAlgoString(x509.DSAWithSHA256) != "SHA256" {
		t.Fatal("standin")
	}
	if HashAlgoString(x509.ECDSAWithSHA1) != "SHA1" {
		t.Fatal("standin")
	}
	if HashAlgoString(x509.ECDSAWithSHA256) != "SHA256" {
		t.Fatal("standin")
	}
	if HashAlgoString(x509.ECDSAWithSHA384) != "SHA384" {
		t.Fatal("standin")
	}
	if HashAlgoString(x509.ECDSAWithSHA512) != "SHA512" {
		t.Fatal("standin")
	}
	if HashAlgoString(math.MaxInt32) != "Unknown Hash Algorithm" {
		t.Fatal("standin")
	}
}

func TestSignatureString(t *testing.T) {
	if SignatureString(x509.MD2WithRSA) != "MD2WithRSA" {
		t.Fatal("Signature String functioning improperly")
	}
	if SignatureString(x509.MD5WithRSA) != "MD5WithRSA" {
		t.Fatal("Signature String functioning improperly")
	}
	if SignatureString(x509.SHA1WithRSA) != "SHA1WithRSA" {
		t.Fatal("Signature String functioning improperly")
	}
	if SignatureString(x509.SHA256WithRSA) != "SHA256WithRSA" {
		t.Fatal("Signature String functioning improperly")
	}
	if SignatureString(x509.SHA384WithRSA) != "SHA384WithRSA" {
		t.Fatal("Signature String functioning improperly")
	}
	if SignatureString(x509.SHA512WithRSA) != "SHA512WithRSA" {
		t.Fatal("Signature String functioning improperly")
	}
	if SignatureString(x509.DSAWithSHA1) != "DSAWithSHA1" {
		t.Fatal("Signature String functioning improperly")
	}
	if SignatureString(x509.DSAWithSHA256) != "DSAWithSHA256" {
		t.Fatal("Signature String functioning improperly")
	}
	if SignatureString(x509.ECDSAWithSHA1) != "ECDSAWithSHA1" {
		t.Fatal("Signature String functioning improperly")
	}
	if SignatureString(x509.ECDSAWithSHA256) != "ECDSAWithSHA256" {
		t.Fatal("Signature String functioning improperly")
	}
	if SignatureString(x509.ECDSAWithSHA384) != "ECDSAWithSHA384" {
		t.Fatal("Signature String functioning improperly")
	}
	if SignatureString(x509.ECDSAWithSHA512) != "ECDSAWithSHA512" {
		t.Fatal("Signature String functioning improperly")
	}
	if SignatureString(math.MaxInt32) != "Unknown Signature" {
		t.Fatal("Signature String functioning improperly")
	}
}

func TestParseCertificatePEM(t *testing.T) {
	for _, testFile := range []string{testCertFile, testExtraWSCertFile} {
		certPEM, err := ioutil.ReadFile(testFile)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := ParseCertificatePEM(certPEM); err != nil {
			t.Fatal(err)
		}
	}
	for _, testFile := range []string{testBundleFile, testMessedUpCertFile, testEmptyCertFile} {
		certPEM, err := ioutil.ReadFile(testFile)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := ParseCertificatePEM(certPEM); err == nil {
			t.Fatal("Incorrect cert failed to raise error")
		}
	}
}

func TestParseCertificatesPEM(t *testing.T) {
	// expected cases
	for _, testFile := range []string{testBundleFile, testExtraWSBundleFile} {
		bundlePEM, err := ioutil.ReadFile(testFile)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := ParseCertificatesPEM(bundlePEM); err != nil {
			t.Fatal(err)
		}
	}
	// test failure cases
	// few lines deleted, then headers removed
	for _, testFile := range []string{testMessedUpBundleFile, testNoHeaderCert} {
		bundlePEM, err := ioutil.ReadFile(testFile)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := ParseCertificatesPEM(bundlePEM); err == nil {
			t.Fatal("Incorrectly-formatted file failed to produce an error")
		}
	}
}

func TestSelfSignedCertificatePEM(t *testing.T) {
	testPEM, _ := ioutil.ReadFile(testCertFile)
	_, err := ParseSelfSignedCertificatePEM(testPEM)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// a few lines deleted from the pem file
	wrongPEM, _ := ioutil.ReadFile(testMessedUpCertFile)
	_, err2 := ParseSelfSignedCertificatePEM(wrongPEM)
	if err2 == nil {
		t.Fatal("Improper pem file failed to raise an error")
	}

	// alter the signature of a valid certificate
	blk, _ := pem.Decode(testPEM)
	blk.Bytes[len(blk.Bytes)-10]++ // some hacking to get to the sig
	alteredBytes := pem.EncodeToMemory(blk)
	_, err = ParseSelfSignedCertificatePEM(alteredBytes)
	if err == nil {
		t.Fatal("Incorrect cert failed to produce an error")
	}

}

func TestParsePrivateKeyPEM(t *testing.T) {

	// expected case
	testPEM, _ := ioutil.ReadFile(testPrivateKey)
	_, err := ParsePrivateKeyPEM(testPEM)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// error cases
	errCases := []string{
		testMessedUpPrivateKey,  // a few lines deleted
		testEmptyPem,            //empty file
		testEncryptedPrivateKey, // encrypted key
	}

	for _, fname := range errCases {
		testPEM, _ = ioutil.ReadFile(fname)
		_, err = ParsePrivateKeyPEM(testPEM)
		if err == nil {
			t.Fatal("Incorrect private key failed to produce an error")
		}
	}

}
