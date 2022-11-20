package helpers

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math"
	"os"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go"
	"golang.org/x/crypto/ocsp"
)

const (
	testCertFile                 = "testdata/cert.pem"
	testCertDERFile              = "testdata/cert.der"
	testBundleFile               = "testdata/bundle.pem"
	testExtraWSCertFile          = "testdata/cert_with_whitespace.pem"
	testExtraWSBundleFile        = "testdata/bundle_with_whitespace.pem"
	testMessedUpBundleFile       = "testdata/messed_up_bundle.pem"
	testMessedUpCertFile         = "testdata/messedupcert.pem"
	testEmptyCertFile            = "testdata/emptycert.pem"
	testPrivateRSAKey            = "testdata/priv_rsa_key.pem"
	testPrivateECDSAKey          = "testdata/private_ecdsa_key.pem"
	testPrivateEd25519Key        = "testdata/private_ed25519_key.pem"
	testPrivateOpenSSLECKey      = "testdata/openssl_secp384.pem"
	testUnsupportedECDSAKey      = "testdata/secp256k1-key.pem"
	testMessedUpPrivateKey       = "testdata/messed_up_priv_key.pem"
	testEncryptedPrivateKey      = "testdata/enc_priv_key.pem"
	testEmptyPem                 = "testdata/empty.pem"
	testNoHeaderCert             = "testdata/noheadercert.pem"
	testSinglePKCS7              = "testdata/cert_pkcs7.pem"  // openssl crl2pkcs7 -nocrl -out cert_pkcs7.pem -in cert.pem
	testEmptyPKCS7DER            = "testdata/empty_pkcs7.der" // openssl crl2pkcs7 -nocrl -out empty_pkcs7.der -outform der
	testEmptyPKCS7PEM            = "testdata/empty_pkcs7.pem" // openssl crl2pkcs7 -nocrl -out empty_pkcs7.pem -outform pem
	testMultiplePKCS7            = "testdata/bundle_pkcs7.pem"
	testPKCS12EmptyPswd          = "testdata/emptypasswordpkcs12.p12"
	testPKCS12Passwordispassword = "testdata/passwordpkcs12.p12"
	testPKCS12MultipleCerts      = "testdata/multiplecerts.p12"
	testCSRPEM                   = "testdata/test.csr.pem"
	testCSRPEMBad                = "testdata/test.bad.csr.pem"
)

func TestParseCertificatesDER(t *testing.T) {
	var password = []string{"password", "", ""}
	for i, testFile := range []string{testPKCS12Passwordispassword, testPKCS12EmptyPswd, testCertDERFile} {
		testDER, err := os.ReadFile(testFile)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := ParseCertificatesDER(testDER, password[i]); err != nil {
			t.Fatal(err)
		}
		// Incorrect Password for PKCS12 formatted files
		if _, _, err := ParseCertificatesDER(testDER, "incorrectpassword"); err == nil && i != 2 {
			t.Fatal(err)
		}
	}

	testDER, err := os.ReadFile(testEmptyPKCS7DER)
	if err != nil {
		t.Fatal(err)
	}
	// PKCS7 with no certificates
	if _, _, err := ParseCertificatesDER(testDER, ""); err == nil {
		t.Fatal(err)
	}
}

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

	// test the ecdsa branch
	ecdsaPriv, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	ecdsaIn, _ := ecdsaPriv.Public().(*ecdsa.PublicKey)
	expEcdsa := ecdsaIn.Curve.Params().BitSize
	outEcdsa := KeyLength(ecdsaIn)
	if expEcdsa != outEcdsa {
		t.Fatal("KeyLength malfunctioning on ecdsa input")
	}

	// test the rsa branch
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
	var expNil time.Time
	inNil := []*x509.Certificate{}
	outNil := ExpiryTime(inNil)
	if expNil != outNil {
		t.Fatal("Expiry time is malfunctioning on empty input")
	}

	// read a pem file and use that expiry date
	bytes, _ := os.ReadFile(testBundleFile)
	certs, err := ParseCertificatesPEM(bytes)
	if err != nil {
		t.Fatalf("%v", err)
	}
	expected := time.Date(2014, time.April, 15, 0, 0, 0, 0, time.UTC)
	out := ExpiryTime(certs)
	if out != expected {
		t.Fatalf("Expected %v, got %v", expected, out)
	}
}

func TestMonthsValid(t *testing.T) {
	var cert = &x509.Certificate{
		NotBefore: time.Date(2015, time.April, 01, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2015, time.April, 01, 0, 0, 0, 0, time.UTC),
	}

	if MonthsValid(cert) != 0 {
		t.Fail()
	}

	cert.NotAfter = time.Date(2016, time.April, 01, 0, 0, 0, 0, time.UTC)
	if MonthsValid(cert) != 12 {
		t.Fail()
	}

	// extra days should be rounded up to 1 month
	cert.NotAfter = time.Date(2016, time.April, 02, 0, 0, 0, 0, time.UTC)
	if MonthsValid(cert) != 13 {
		t.Fail()
	}
}

func TestHasValidExpiry(t *testing.T) {
	// Issue period > April 1, 2015
	var cert = &x509.Certificate{
		NotBefore: time.Date(2015, time.April, 01, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2016, time.April, 01, 0, 0, 0, 0, time.UTC),
	}

	if !ValidExpiry(cert) {
		t.Fail()
	}

	cert.NotAfter = time.Date(2019, time.April, 01, 01, 0, 0, 0, time.UTC)
	if ValidExpiry(cert) {
		t.Fail()
	}

	// Issue period < July 1, 2012
	cert.NotBefore = time.Date(2009, time.March, 01, 0, 0, 0, 0, time.UTC)
	if ValidExpiry(cert) {
		t.Fail()
	}

	// Issue period July 1, 2012 - April 1, 2015
	cert.NotBefore = time.Date(2012, time.July, 01, 0, 0, 0, 0, time.UTC)
	cert.NotAfter = time.Date(2017, time.July, 01, 0, 0, 0, 0, time.UTC)
	if !ValidExpiry(cert) {
		t.Fail()
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
	for _, testFile := range []string{testCertFile, testExtraWSCertFile, testSinglePKCS7} {
		certPEM, err := os.ReadFile(testFile)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := ParseCertificatePEM(certPEM); err != nil {
			t.Log(testFile)
			t.Fatal(err)
		}
	}
	for _, testFile := range []string{testBundleFile, testMessedUpCertFile, testEmptyPKCS7PEM, testEmptyCertFile, testMultiplePKCS7} {
		certPEM, err := os.ReadFile(testFile)
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
	for _, testFile := range []string{testBundleFile, testExtraWSBundleFile, testSinglePKCS7, testMultiplePKCS7} {
		bundlePEM, err := os.ReadFile(testFile)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := ParseCertificatesPEM(bundlePEM); err != nil {
			t.Log(testFile)
			t.Fatal(err)
		}
	}

	// test failure cases
	// few lines deleted, then headers removed
	for _, testFile := range []string{testMessedUpBundleFile, testEmptyPKCS7PEM, testNoHeaderCert} {
		bundlePEM, err := os.ReadFile(testFile)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := ParseCertificatesPEM(bundlePEM); err == nil {
			t.Fatal("Incorrectly-formatted file failed to produce an error")
		}
	}
}

func TestSelfSignedCertificatePEM(t *testing.T) {
	testPEM, err := os.ReadFile(testCertFile)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseSelfSignedCertificatePEM(testPEM)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// a few lines deleted from the pem file
	wrongPEM, err := os.ReadFile(testMessedUpCertFile)
	if err != nil {
		t.Fatal(err)
	}
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

	// expected cases
	testRSAPEM, err := os.ReadFile(testPrivateRSAKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParsePrivateKeyPEM(testRSAPEM)
	if err != nil {
		t.Fatal(err)
	}

	testECDSAPEM, err := os.ReadFile(testPrivateECDSAKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParsePrivateKeyPEM(testECDSAPEM)
	if err != nil {
		t.Fatal(err)
	}

	testEd25519PEM, err := os.ReadFile(testPrivateEd25519Key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ParsePrivateKeyPEM(testEd25519PEM)
	if err != nil {
		t.Fatal(err)
	}

	testOpenSSLECKey, err := os.ReadFile(testPrivateOpenSSLECKey)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ParsePrivateKeyPEM(testOpenSSLECKey)
	if err != nil {
		t.Fatal(err)
	}

	// error cases
	errCases := []string{
		testMessedUpPrivateKey,  // a few lines deleted
		testEmptyPem,            // empty file
		testEncryptedPrivateKey, // encrypted key
		testUnsupportedECDSAKey, // ECDSA curve not currently supported by Go standard library
	}

	for _, fname := range errCases {
		testPEM, _ := os.ReadFile(fname)
		_, err = ParsePrivateKeyPEM(testPEM)
		if err == nil {
			t.Fatal("Incorrect private key failed to produce an error")
		}
	}

}

// Imported from signers/local/testdata/
const ecdsaTestCSR = "testdata/ecdsa256.csr"

func TestParseCSRPEM(t *testing.T) {
	in, err := os.ReadFile(ecdsaTestCSR)
	if err != nil {
		t.Fatalf("%v", err)
	}

	_, _, err = ParseCSR(in)
	if err != nil {
		t.Fatalf("%v", err)
	}

	in[12]++
	_, _, err = ParseCSR(in)
	if err == nil {
		t.Fatalf("Expected an invalid CSR.")
	}
	in[12]--
}

func TestParseCSRPEMMore(t *testing.T) {
	csrPEM, err := os.ReadFile(testCSRPEM)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ParseCSRPEM(csrPEM); err != nil {
		t.Fatal(err)
	}

	csrPEM, err = os.ReadFile(testCSRPEMBad)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ParseCSRPEM(csrPEM); err == nil {
		t.Fatal(err)
	}

	if _, err := ParseCSRPEM([]byte("not even pem")); err == nil {
		t.Fatal("Expected an invalid CSR.")
	}
}

// Imported from signers/local/testdata/
const rsaOldTestCSR = "testdata/rsa-old.csr"

func TestParseOldCSR(t *testing.T) {
	in, err := os.ReadFile(rsaOldTestCSR)
	if err != nil {
		t.Fatalf("%v", err)
	}

	_, _, err = ParseCSR(in)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

// Imported from signers/local/testdata/
const clientCertFile = "testdata/ca.pem"
const clientKeyFile = "testdata/ca_key.pem"

func TestClientCertParams(t *testing.T) {
	_, err := LoadClientCertificate(testCertFile, testPrivateRSAKey)
	if err == nil {
		t.Fatal("Unmatched cert/key should generate error")
	}

	cert, err := LoadClientCertificate("", "")
	if err != nil || cert != nil {
		t.Fatal("Certificate atempted to loaded with missing key and cert")
	}
	cert, err = LoadClientCertificate(clientCertFile, "")
	if err != nil || cert != nil {
		t.Fatal("Certificate atempted to loaded with missing key")
	}
	cert, err = LoadClientCertificate("", clientKeyFile)
	if err != nil || cert != nil {
		t.Fatal("Certificate atempted to loaded with missing cert")
	}

	cert, err = LoadClientCertificate(clientCertFile, clientKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if cert == nil {
		t.Fatal("cert not created")
	}
}

func TestLoadPEMCertPool(t *testing.T) {
	certPool, err := PEMToCertPool([]byte{})
	if certPool != nil || err != nil {
		t.Fatal("Empty file name should not generate error or a cert pool")
	}

	in, err := os.ReadFile(testEmptyPem)
	if err != nil {
		t.Fatalf("%v", err)
	}
	certPool, err = PEMToCertPool(in)
	if certPool != nil {
		t.Fatal("Empty file should not generate a cert pool")
	} else if err == nil {
		t.Fatal("Expected error for empty file")
	}

	in, err = os.ReadFile(testEmptyCertFile)
	if err != nil {
		t.Fatalf("%v", err)
	}
	certPool, err = PEMToCertPool(in)
	if certPool != nil {
		t.Fatal("Empty cert should not generate a cert pool")
	} else if err == nil {
		t.Fatal("Expected error for empty cert")
	}

	in, err = os.ReadFile(clientCertFile)
	if err != nil {
		t.Fatalf("%v", err)
	}
	certPool, err = PEMToCertPool(in)
	if err != nil {
		t.Fatalf("%v", err)
	} else if certPool == nil {
		t.Fatal("cert pool not created")
	}
}

// sctEquals returns true if all fields of both SCTs are equivalent.
func sctEquals(sctA, sctB ct.SignedCertificateTimestamp) bool {
	if sctA.SCTVersion == sctB.SCTVersion &&
		sctA.LogID == sctB.LogID &&
		sctA.Timestamp == sctB.Timestamp &&
		bytes.Equal(sctA.Extensions, sctB.Extensions) &&
		sctA.Signature.Algorithm == sctB.Signature.Algorithm &&
		bytes.Equal(sctA.Signature.Signature, sctA.Signature.Signature) {
		return true
	}
	return false
}

// NOTE: TestDeserializeSCTList tests both DeserializeSCTList and
// SerializeSCTList.
func TestDeserializeSCTList(t *testing.T) {
	// Here we make sure that empty SCT lists return an error
	emptyLists := [][]byte{nil, {}}
	for _, emptyList := range emptyLists {
		_, err := DeserializeSCTList(emptyList)
		if err == nil {
			t.Fatalf("DeserializeSCTList(%v) should raise an error\n", emptyList)
		}
	}

	// Here we make sure that an SCT list with a zero SCT is deserialized
	// correctly
	var zeroSCT ct.SignedCertificateTimestamp
	serializedSCT, err := SerializeSCTList([]ct.SignedCertificateTimestamp{zeroSCT})
	if err != nil {
		t.Fatal(err)
	}
	deserializedSCTList, err := DeserializeSCTList(serializedSCT)
	if err != nil {
		t.Fatal(err)
	}
	if !sctEquals(zeroSCT, (deserializedSCTList)[0]) {
		t.Fatal("SCTs don't match")
	}

	// Here we verify that an error is raised when the SCT list length
	// field is greater than its actual length
	serializedSCT, err = SerializeSCTList([]ct.SignedCertificateTimestamp{zeroSCT})
	if err != nil {
		t.Fatal(err)
	}
	serializedSCT[0] = 15
	_, err = DeserializeSCTList(serializedSCT)
	if err == nil {
		t.Fatalf("DeserializeSCTList should raise an error when " +
			"the SCT list length field and the list length don't match\n")
	}

	// Here we verify that an error is raised when the SCT list length
	// field is less than its actual length
	serializedSCT[0] = 0
	serializedSCT[1] = 0
	_, err = DeserializeSCTList(serializedSCT)
	if err == nil {
		t.Fatalf("DeserializeSCTList should raise an error when " +
			"the SCT list length field and the list length don't match\n")
	}

	// Here we verify that an error is raised when the SCT length field is
	// greater than its actual length
	serializedSCT[0] = 0
	serializedSCT[1] = 49
	serializedSCT[2] = 1
	_, err = DeserializeSCTList(serializedSCT)
	if err == nil {
		t.Fatalf("DeserializeSCTList should raise an error when " +
			"the SCT length field and the SCT length don't match\n")
	}

	// Here we verify that an error is raised when the SCT length field is
	// less than its actual length
	serializedSCT[2] = 0
	serializedSCT[3] = 0
	_, err = DeserializeSCTList(serializedSCT)
	if err == nil {
		t.Fatalf("DeserializeSCTList should raise an error when " +
			"the SCT length field and the SCT length don't match\n")
	}
}

func TestSCTListFromOCSPResponse(t *testing.T) {
	var response ocsp.Response
	lst, err := SCTListFromOCSPResponse(&response)
	if err != nil {
		t.Fatal(err)
	}
	if len(lst) != 0 {
		t.Fatal("SCTListFromOCSPResponse should return an empty SCT list for an empty extension")
	}

	var zeroSCT ct.SignedCertificateTimestamp
	serializedSCTList, err := SerializeSCTList([]ct.SignedCertificateTimestamp{zeroSCT})
	if err != nil {
		t.Fatal("failed to serialize SCT list")
	}
	serializedSCTList, err = asn1.Marshal(serializedSCTList)
	if err != nil {
		t.Fatal("failed to serialize SCT list")
	}
	// The value of Id below is the object identifier of the OCSP Stapling
	// SCT extension (see section 3.3. of RFC 6962).
	response.Extensions = []pkix.Extension{{
		Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 5},
		Critical: false,
		Value:    serializedSCTList,
	}}
	lst, err = SCTListFromOCSPResponse(&response)
	if err != nil {
		t.Fatal(err)
	}
	if !sctEquals(zeroSCT, lst[0]) {
		t.Fatal("SCTs don't match")
	}
}
