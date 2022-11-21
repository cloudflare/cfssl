package csr

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"os"
	"testing"

	"github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/helpers"
)

// TestNew validate the CertificateRequest created to return with a KeyRequest
// in KeyRequest field
func TestNew(t *testing.T) {
	if cr := New(); cr.KeyRequest == nil {
		t.Fatalf("Should create a new, empty certificate request with KeyRequest")
	}
}

// TestKeyRequest ensures that key generation returns the same type of
// key specified in the KeyRequest.
func TestKeyRequest(t *testing.T) {
	kr := NewKeyRequest()
	priv, err := kr.Generate()
	if err != nil {
		t.Fatalf("%v", err)
	}

	switch priv.(type) {
	case *rsa.PrivateKey:
		if kr.Algo() != "rsa" {
			t.Fatal("RSA key generated, but expected", kr.Algo())
		}
	case *ecdsa.PrivateKey:
		if kr.Algo() != "ecdsa" {
			t.Fatal("ECDSA key generated, but expected", kr.Algo())
		}
	}
}

// TestPKIXName validates building a pkix.Name structure from a
// CertificateRequest.
func TestPKIXName(t *testing.T) {
	var cr = &CertificateRequest{
		CN: "Test Common Name",
		Names: []Name{
			{
				C:  "US",
				ST: "California",
				L:  "San Francisco",
				O:  "CloudFlare, Inc.",
				OU: "Systems Engineering",
			},
			{
				C:  "GB",
				ST: "London",
				L:  "London",
				O:  "CloudFlare, Inc",
				OU: "Systems Engineering",
			},
		},
		Hosts:      []string{"cloudflare.com", "www.cloudflare.com"},
		KeyRequest: NewKeyRequest(),
	}

	name, err := cr.Name()
	if err != nil {
		t.Fatalf("Error getting name: %s", err.Error())
	}
	if len(name.Country) != 2 {
		t.Fatal("Expected two countries in SubjInfo.")
	} else if len(name.Province) != 2 {
		t.Fatal("Expected two states in SubjInfo.")
	} else if len(name.Locality) != 2 {
		t.Fatal("Expected two localities in SubjInfo.")
	} else if len(name.Country) != 2 {
		t.Fatal("Expected two countries in SubjInfo.")
	} else if len(name.Organization) != 2 {
		t.Fatal("Expected two organization in SubjInfo.")
	} else if len(name.OrganizationalUnit) != 2 {
		t.Fatal("Expected two organizational units in SubjInfo.")
	}
}

// TestParseRequest ensures that a valid certificate request does not
// error.
func TestParseRequest(t *testing.T) {
	var cr = &CertificateRequest{
		CN: "Test Common Name",
		Names: []Name{
			{
				C:  "US",
				ST: "California",
				L:  "San Francisco",
				O:  "CloudFlare, Inc.",
				OU: "Systems Engineering",
			},
			{
				C:  "GB",
				ST: "London",
				L:  "London",
				O:  "CloudFlare, Inc",
				OU: "Systems Engineering",
			},
		},
		Hosts:      []string{"cloudflare.com", "www.cloudflare.com", "192.168.0.1", "jdoe@example.com", "https://www.cloudflare.com"},
		KeyRequest: NewKeyRequest(),
		Extensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{1, 2, 3, 4, 5},
				Value: []byte("AgEB"),
			},
		},
	}

	csrBytes, _, err := ParseRequest(cr)
	if err != nil {
		t.Fatalf("%v", err)
	}

	block, _ := pem.Decode(csrBytes)
	if block == nil {
		t.Fatalf("%v", err)
	}

	if block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("Incorrect block type: %s", block.Type)
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("%v", err)
	}

	found := false
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{1, 2, 3, 4, 5}) {
			found = true
			break
		}
	}

	if !found {
		t.Fatalf("CSR did not include Custom Extension")
	}
}

// TestParseRequestCA ensures that a valid CA certificate request does not
// error and the resulting CSR includes the BasicConstraint extension
func TestParseRequestCA(t *testing.T) {
	var cr = &CertificateRequest{
		CN: "Test Common Name",
		Names: []Name{
			{
				C:  "US",
				ST: "California",
				L:  "San Francisco",
				O:  "CloudFlare, Inc.",
				OU: "Systems Engineering",
			},
			{
				C:  "GB",
				ST: "London",
				L:  "London",
				O:  "CloudFlare, Inc",
				OU: "Systems Engineering",
			},
		},
		CA: &CAConfig{
			PathLength:  0,
			PathLenZero: true,
		},
		KeyRequest: NewKeyRequest(),
	}

	csrBytes, _, err := ParseRequest(cr)
	if err != nil {
		t.Fatalf("%v", err)
	}

	block, _ := pem.Decode(csrBytes)
	if block == nil {
		t.Fatalf("%v", err)
	}

	if block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("Incorrect block type: %s", block.Type)
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("%v", err)
	}

	found := false
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 19}) {
			found = true
			break
		}
	}

	if !found {
		t.Fatalf("CSR did not include BasicConstraint Extension")
	}
}

// TestParseRequestCANoPathlen ensures that a valid CA certificate request
// with an unspecified pathlen does not error and the resulting CSR includes
// the BasicConstraint extension
func TestParseRequestCANoPathlen(t *testing.T) {
	var cr = &CertificateRequest{
		CN: "Test Common Name",
		Names: []Name{
			{
				C:  "US",
				ST: "California",
				L:  "San Francisco",
				O:  "CloudFlare, Inc.",
				OU: "Systems Engineering",
			},
			{
				C:  "GB",
				ST: "London",
				L:  "London",
				O:  "CloudFlare, Inc",
				OU: "Systems Engineering",
			},
		},
		CA: &CAConfig{
			PathLength:  0,
			PathLenZero: false,
		},
		KeyRequest: NewKeyRequest(),
	}

	csrBytes, _, err := ParseRequest(cr)
	if err != nil {
		t.Fatalf("%v", err)
	}

	block, _ := pem.Decode(csrBytes)
	if block == nil {
		t.Fatalf("%v", err)
	}

	if block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("Incorrect block type: %s", block.Type)
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("%v", err)
	}

	found := false
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 19}) {
			bc := &BasicConstraints{}
			asn1.Unmarshal(ext.Value, bc)
			if bc.IsCA == true && bc.MaxPathLen == -1 {
				found = true
				break
			}
		}
	}

	if !found {
		t.Fatalf("CSR did not include BasicConstraint Extension")
	}
}

func whichCurve(sz int) elliptic.Curve {
	switch sz {
	case 256:
		return elliptic.P256()
	case 384:
		return elliptic.P384()
	case 521:
		return elliptic.P521()
	}
	return nil
}

// TestECGeneration ensures that the proper curve is used depending on
// the bit size specified in a key request and that an appropriate
// signature algorithm is returned.
func TestECGeneration(t *testing.T) {
	var eckey *ecdsa.PrivateKey

	for _, sz := range []int{256, 384, 521} {
		kr := &KeyRequest{"ecdsa", sz}
		priv, err := kr.Generate()
		if err != nil {
			t.Fatalf("%v", err)
		}
		eckey = priv.(*ecdsa.PrivateKey)
		if eckey.Curve != whichCurve(sz) {
			t.Fatal("Generated key has wrong curve.")
		}
		if sa := kr.SigAlgo(); sa == x509.UnknownSignatureAlgorithm {
			t.Fatal("Invalid signature algorithm!")
		}
	}
}

func TestRSAKeyGeneration(t *testing.T) {
	var rsakey *rsa.PrivateKey

	for _, sz := range []int{2048, 3072, 4096} {
		kr := &KeyRequest{"rsa", sz}
		priv, err := kr.Generate()
		if err != nil {
			t.Fatalf("%v", err)
		}
		rsakey = priv.(*rsa.PrivateKey)
		if rsakey.PublicKey.N.BitLen() != kr.Size() {
			t.Fatal("Generated key has wrong size.")
		}
		if sa := kr.SigAlgo(); sa == x509.UnknownSignatureAlgorithm {
			t.Fatal("Invalid signature algorithm!")
		}
	}
}

// TestBadKeyRequest ensures that generating a key from a KeyRequest
// fails with an invalid algorithm, or an invalid RSA or ECDSA key
// size. An invalid ECDSA key size is any size other than 256, 384, or
// 521; an invalid RSA key size is any size less than 2048 bits.
func TestBadKeyRequest(t *testing.T) {
	kr := &KeyRequest{"yolocrypto", 1024}

	if _, err := kr.Generate(); err == nil {
		t.Fatal("Key generation should fail with invalid algorithm")
	} else if sa := kr.SigAlgo(); sa != x509.UnknownSignatureAlgorithm {
		t.Fatal("The wrong signature algorithm was returned from SigAlgo!")
	}

	kr.A = "ecdsa"
	if _, err := kr.Generate(); err == nil {
		t.Fatal("Key generation should fail with invalid key size")
	} else if sa := kr.SigAlgo(); sa != x509.ECDSAWithSHA1 {
		t.Fatal("The wrong signature algorithm was returned from SigAlgo!")
	}

	kr.A = "rsa"
	if _, err := kr.Generate(); err == nil {
		t.Fatal("Key generation should fail with invalid key size")
	} else if sa := kr.SigAlgo(); sa != x509.SHA1WithRSA {
		t.Fatal("The wrong signature algorithm was returned from SigAlgo!")
	}

	kr = &KeyRequest{"tobig", 9216}

	kr.A = "rsa"
	if _, err := kr.Generate(); err == nil {
		t.Fatal("Key generation should fail with invalid key size")
	} else if sa := kr.SigAlgo(); sa != x509.SHA512WithRSA {
		t.Fatal("The wrong signature algorithm was returned from SigAlgo!")
	}
}

// TestDefaultKeyRequest makes sure that certificate requests without
// explicit key requests fall back to the default key request.
func TestDefaultKeyRequest(t *testing.T) {
	var req = &CertificateRequest{
		Names: []Name{
			{
				C:  "US",
				ST: "California",
				L:  "San Francisco",
				O:  "CloudFlare",
				OU: "Systems Engineering",
			},
		},
		CN:    "cloudflare.com",
		Hosts: []string{"cloudflare.com", "www.cloudflare.com", "jdoe@example.com", "https://www.cloudflare.com"},
	}
	_, priv, err := ParseRequest(req)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// If the default key type changes, this will need to be changed.
	block, _ := pem.Decode(priv)
	if block == nil {
		t.Fatal("Bad private key was generated!")
	}

	DefaultKeyRequest := NewKeyRequest()
	switch block.Type {
	case "RSA PRIVATE KEY":
		if DefaultKeyRequest.Algo() != "rsa" {
			t.Fatal("Invalid default key request.")
		}
	case "EC PRIVATE KEY":
		if DefaultKeyRequest.Algo() != "ecdsa" {
			t.Fatal("Invalid default key request.")
		}
	}
}

// TestRSACertRequest validates parsing a certificate request with an
// RSA key.
func TestRSACertRequest(t *testing.T) {
	var req = &CertificateRequest{
		Names: []Name{
			{
				C:  "US",
				ST: "California",
				L:  "San Francisco",
				O:  "CloudFlare",
				OU: "Systems Engineering",
			},
		},
		CN:         "cloudflare.com",
		Hosts:      []string{"cloudflare.com", "www.cloudflare.com", "jdoe@example.com", "https://www.cloudflare.com"},
		KeyRequest: &KeyRequest{"rsa", 2048},
	}
	_, _, err := ParseRequest(req)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

// TestBadCertRequest checks for failure conditions of ParseRequest.
func TestBadCertRequest(t *testing.T) {
	var req = &CertificateRequest{
		Names: []Name{
			{
				C:  "US",
				ST: "California",
				L:  "San Francisco",
				O:  "CloudFlare",
				OU: "Systems Engineering",
			},
		},
		CN:         "cloudflare.com",
		Hosts:      []string{"cloudflare.com", "www.cloudflare.com"},
		KeyRequest: &KeyRequest{"yolo-crypto", 2048},
	}
	_, _, err := ParseRequest(req)
	if err == nil {
		t.Fatal("ParseRequest should fail with a bad key algorithm.")
	}
}

// testValidator is a stripped-down validator that checks to make sure
// the request has a common name. It should mimic some of the
// functionality expected in an actual validator.
func testValidator(req *CertificateRequest) error {
	if req.CN == "" {
		return errors.NewBadRequestMissingParameter("CN")
	}

	return nil
}

// TestGenerator ensures that a valid request is processed properly
// and returns a certificate request and key.
func TestGenerator(t *testing.T) {
	g := &Generator{testValidator}
	var req = &CertificateRequest{
		Names: []Name{
			{
				C:  "US",
				ST: "California",
				L:  "San Francisco",
				O:  "CloudFlare",
				OU: "Systems Engineering",
			},
		},
		CN:         "cloudflare.com",
		Hosts:      []string{"cloudflare.com", "www.cloudflare.com", "192.168.0.1", "jdoe@example.com", "https://www.cloudflare.com"},
		KeyRequest: &KeyRequest{"rsa", 2048},
	}

	csrBytes, _, err := g.ProcessRequest(req)
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode([]byte(csrBytes))
	if block == nil {
		t.Fatalf("bad CSR in PEM")
	}

	if block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("bad CSR in PEM")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	if len(csr.DNSNames) != 2 {
		t.Fatal("SAN parsing error")
	}

	if len(csr.IPAddresses) != 1 {
		t.Fatal("SAN parsing error")
	}

	if len(csr.EmailAddresses) != 1 {
		t.Fatal("SAN parsing error")
	}

	if len(csr.URIs) != 1 {
		t.Fatal("SAN parsing error")
	}

}

// TestBadGenerator ensures that a request that fails the validator is
// not processed.
func TestBadGenerator(t *testing.T) {
	g := &Generator{testValidator}
	missingCN := &CertificateRequest{
		Names: []Name{
			{
				C:  "US",
				ST: "California",
				L:  "San Francisco",
				O:  "CloudFlare",
				OU: "Systems Engineering",
			},
		},
		// Missing CN
		Hosts:      []string{"cloudflare.com", "www.cloudflare.com"},
		KeyRequest: &KeyRequest{"rsa", 2048},
	}

	_, _, err := g.ProcessRequest(missingCN)
	if err == nil {
		t.Fatalf("Request should have failed.")
	}
}

func TestWeakCSR(t *testing.T) {
	weakKey := &CertificateRequest{
		Names: []Name{
			{
				C:  "US",
				ST: "California",
				L:  "San Francisco",
				O:  "CloudFlare",
				OU: "Systems Engineering",
			},
		},
		CN:         "cloudflare.com",
		Hosts:      []string{"cloudflare.com", "www.cloudflare.com", "jdoe@example.com", "https://www.cloudflare.com"},
		KeyRequest: &KeyRequest{"rsa", 1024},
	}
	g := &Generator{testValidator}

	_, _, err := g.ProcessRequest(weakKey)
	if err == nil {
		t.Fatalf("Request should have failed.")
	}
}

var testEmpty = []struct {
	name Name
	ok   bool
}{
	{
		Name{},
		true,
	},
	{
		Name{C: "OK"},
		false,
	},
	{
		Name{ST: "OK"},
		false,
	},
	{
		Name{L: "OK"},
		false,
	},
	{
		Name{O: "OK"},
		false,
	},
	{
		Name{OU: "OK"},
		false,
	},
}

func TestIsNameEmpty(t *testing.T) {
	for i, c := range testEmpty {
		if IsNameEmpty(c.name) != c.ok {
			t.Fatalf("%d: expected IsNameEmpty to return %v, but have %v", i, c.ok, !c.ok)
		}
	}
}

func TestGenerate(t *testing.T) {
	var req = &CertificateRequest{
		Names: []Name{
			{
				C:  "US",
				ST: "California",
				L:  "San Francisco",
				O:  "CloudFlare",
				OU: "Systems Engineering",
			},
		},
		CN:         "cloudflare.com",
		Hosts:      []string{"cloudflare.com", "www.cloudflare.com", "192.168.0.1", "jdoe@example.com", "https://www.cloudflare.com"},
		KeyRequest: &KeyRequest{"ecdsa", 256},
	}

	key, err := req.KeyRequest.Generate()
	if err != nil {
		t.Fatalf("%v", err)
	}

	priv, ok := key.(crypto.Signer)
	if !ok {
		t.Fatal("Private key is not a signer.")
	}

	csrPEM, err := Generate(priv, req)
	if err != nil {
		t.Fatalf("%v", err)
	}

	csr, _, err := helpers.ParseCSR(csrPEM)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if len(csr.DNSNames) != 2 {
		t.Fatal("SAN parsing error")
	}

	if len(csr.IPAddresses) != 1 {
		t.Fatal("SAN parsing error")
	}

	if len(csr.EmailAddresses) != 1 {
		t.Fatal("SAN parsing error")
	}

	if len(csr.URIs) != 1 {
		t.Fatal("SAN parsing error")
	}
}

// TestReGenerate ensures Regenerate() is abel to use the provided CSR as a template for signing a new
// CSR using priv.
func TestReGenerate(t *testing.T) {
	var req = &CertificateRequest{
		Names: []Name{
			{
				C:  "US",
				ST: "California",
				L:  "San Francisco",
				O:  "CloudFlare",
				OU: "Systems Engineering",
			},
		},
		CN:         "cloudflare.com",
		Hosts:      []string{"cloudflare.com", "www.cloudflare.com", "192.168.0.1"},
		KeyRequest: &KeyRequest{"ecdsa", 256},
	}

	_, key, err := ParseRequest(req)
	if err != nil {
		t.Fatalf("%v", err)
	}

	priv, err := helpers.ParsePrivateKeyPEM(key)
	if err != nil {
		t.Fatalf("%v", err)
	}

	csr, err := Generate(priv, req)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if _, _, err = helpers.ParseCSR(csr); err != nil {
		t.Fatalf("%v", err)
	}

	_, err = Regenerate(priv, csr)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

// TestBadReGenerator ensures that a request that fails the ParseCSR is
// not processed.
func TestBadReGenerate(t *testing.T) {
	var req = &CertificateRequest{
		Names: []Name{
			{
				C:  "US",
				ST: "California",
				L:  "San Francisco",
				O:  "CloudFlare",
				OU: "Systems Engineering",
			},
		},
		CN:         "cloudflare.com",
		Hosts:      []string{"cloudflare.com", "www.cloudflare.com", "192.168.0.1"},
		KeyRequest: &KeyRequest{"ecdsa", 256},
	}

	_, key, err := ParseRequest(req)
	if err != nil {
		t.Fatalf("%v", err)
	}

	priv, err := helpers.ParsePrivateKeyPEM(key)
	if err != nil {
		t.Fatalf("%v", err)
	}

	csr, err := Generate(priv, req)
	if err != nil {
		t.Fatalf("%v", err)
	}

	block := pem.Block{
		Type: "CERTIFICATE REQUEST",
		Headers: map[string]string{
			"Location": "UCSD",
		},
		Bytes: csr,
	}

	csr = pem.EncodeToMemory(&block)

	_, err = Regenerate(priv, csr)
	if err == nil {
		t.Fatalf("%v", err)
	}
}

var testECDSACertificateFile = "testdata/test-ecdsa-ca.pem"

func TestExtractCertificateRequest(t *testing.T) {
	certPEM, err := os.ReadFile(testECDSACertificateFile)
	if err != nil {
		t.Fatal(err)
	}

	// must parse ok
	cert, err := helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}

	req := ExtractCertificateRequest(cert)

	if req.CN != "" {
		t.Fatal("Bad Certificate Request!")
	}

	if len(req.Names) != 1 {
		t.Fatal("Bad Certificate Request!")
	}

	name := req.Names[0]
	if name.C != "US" || name.ST != "California" || name.O != "CloudFlare, Inc." ||
		name.OU != "Test Certificate Authority" || name.L != "San Francisco" {
		t.Fatal("Bad Certificate Request!")
	}

	if req.CA == nil || req.CA.PathLength != 2 {
		t.Fatal("Bad Certificate Request!")
	}
}

// TestDelegationCSR tests that we create requests with the DC extension
func TestDelegationCSR(t *testing.T) {
	var cr = &CertificateRequest{
		CN: "Test Common Name",
		Names: []Name{
			{
				C:  "US",
				ST: "California",
				L:  "San Francisco",
				O:  "CloudFlare, Inc.",
				OU: "Systems Engineering",
			},
			{
				C:  "GB",
				ST: "London",
				L:  "London",
				O:  "CloudFlare, Inc",
				OU: "Systems Engineering",
			},
		},
		DelegationEnabled: true,
		Hosts:             []string{"cloudflare.com", "www.cloudflare.com"},
		KeyRequest:        NewKeyRequest(),
	}
	csr, _, err := ParseRequest(cr)
	if err != nil {
		t.Fatal("could not generate csr")
	}
	unPem, _ := pem.Decode(csr)
	if unPem == nil {
		t.Fatal("Failed to decode pem")
	}
	res, err := x509.ParseCertificateRequest(unPem.Bytes)
	if err != nil {
		t.Fatalf("spat out nonsense as a csr: %v", err)
	}
	found := false
	for _, ext := range res.Extensions {
		if ext.Id.Equal(helpers.DelegationUsage) {
			found = true
		}
	}
	if !found {
		t.Fatal("generated csr has no extension")
	}
}
