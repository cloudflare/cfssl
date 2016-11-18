package tls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	mathrand "math/rand"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/certificate-transparency/go/testdata"
	"github.com/google/certificate-transparency/go/x509"
)

func TestGenerateHash(t *testing.T) {
	var tests = []struct {
		in     string // hex encoded
		algo   HashAlgorithm
		want   string // hex encoded
		errstr string
	}{
		// Empty hash values
		{"", MD5, "d41d8cd98f00b204e9800998ecf8427e", ""},
		{"", SHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709", ""},
		{"", SHA224, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f", ""},
		{"", SHA256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", ""},
		{"", SHA384, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", ""},
		{"", SHA512, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", ""},
		{"", 999, "", "unsupported"},

		// Hashes of "abcd".
		{"61626364", MD5, testdata.AbcdMD5, ""},
		{"61626364", SHA1, testdata.AbcdSHA1, ""},
		{"61626364", SHA224, testdata.AbcdSHA224, ""},
		{"61626364", SHA256, testdata.AbcdSHA256, ""},
		{"61626364", SHA384, testdata.AbcdSHA384, ""},
		{"61626364", SHA512, testdata.AbcdSHA512, ""},
	}
	for _, test := range tests {
		got, _, err := generateHash(test.algo, testdata.FromHex(test.in))
		if test.errstr != "" {
			if err == nil {
				t.Errorf("generateHash(%s)=%s,nil; want error %q", test.in, hex.EncodeToString(got), test.errstr)
			} else if !strings.Contains(err.Error(), test.errstr) {
				t.Errorf("generateHash(%s)=nil,%q; want error %q", test.in, test.errstr, err.Error())
			}
			continue
		}
		if err != nil {
			t.Errorf("generateHash(%s)=nil,%q; want %s", test.in, err, test.want)
		} else if hex.EncodeToString(got) != test.want {
			t.Errorf("generateHash(%s)=%s,nil; want %s", test.in, hex.EncodeToString(got), test.want)
		}
	}
}

func TestVerifySignature(t *testing.T) {
	var tests = []struct {
		pubKey   crypto.PublicKey
		in       string // hex encoded
		hashAlgo HashAlgorithm
		sigAlgo  SignatureAlgorithm
		errstr   string
		sig      string // hex encoded
	}{
		{PEM2PK(testdata.RsaPublicKeyPEM), "61626364", 99, ECDSA, "unsupported Algorithm.Hash", "1234"},
		{PEM2PK(testdata.RsaPublicKeyPEM), "61626364", SHA256, 99, "unsupported Algorithm.Signature", "1234"},

		{PEM2PK(testdata.RsaPublicKeyPEM), "61626364", SHA256, DSA, "cannot verify DSA", "1234"},
		{PEM2PK(testdata.RsaPublicKeyPEM), "61626364", SHA256, ECDSA, "cannot verify ECDSA", "1234"},
		{PEM2PK(testdata.RsaPublicKeyPEM), "61626364", SHA256, RSA, "verification error", "1234"},
		{PEM2PK(testdata.RsaPublicKeyPEM), "61626364", SHA256, ECDSA, "cannot verify ECDSA", "1234"},

		{PEM2PK(testdata.DsaPublicKeyPEM), "61626364", SHA1, RSA, "cannot verify RSA", "1234"},
		{PEM2PK(testdata.DsaPublicKeyPEM), "61626364", SHA1, ECDSA, "cannot verify ECDSA", "1234"},
		{PEM2PK(testdata.DsaPublicKeyPEM), "61626364", SHA1, DSA, "failed to unmarshal DSA signature", "1234"},
		{PEM2PK(testdata.DsaPublicKeyPEM), "61626364", SHA1, DSA, "failed to verify DSA signature", "3006020101020101eeff"},
		{PEM2PK(testdata.DsaPublicKeyPEM), "61626364", SHA1, DSA, "zero or negative values", "3006020100020181"},

		{PEM2PK(testdata.EcdsaPublicKeyPEM), "61626364", SHA256, RSA, "cannot verify RSA", "1234"},
		{PEM2PK(testdata.EcdsaPublicKeyPEM), "61626364", SHA256, DSA, "cannot verify DSA", "1234"},
		{PEM2PK(testdata.EcdsaPublicKeyPEM), "61626364", SHA256, ECDSA, "failed to unmarshal ECDSA signature", "1234"},
		{PEM2PK(testdata.EcdsaPublicKeyPEM), "61626364", SHA256, ECDSA, "failed to verify ECDSA signature", "3006020101020101eeff"},
		{PEM2PK(testdata.EcdsaPublicKeyPEM), "61626364", SHA256, ECDSA, "zero or negative values", "3006020100020181"},

		{PEM2PK(testdata.RsaPublicKeyPEM), "61626364", SHA256, RSA, "", testdata.RsaSignedAbcdHex},
		{PEM2PK(testdata.DsaPublicKeyPEM), "61626364", SHA1, DSA, "", testdata.DsaSignedAbcdHex},
		{PEM2PK(testdata.EcdsaPublicKeyPEM), "61626364", SHA256, ECDSA, "", testdata.EcdsaSignedAbcdHex},
	}
	for _, test := range tests {
		algo := SignatureAndHashAlgorithm{Hash: test.hashAlgo, Signature: test.sigAlgo}
		signed := DigitallySigned{Algorithm: algo, Signature: testdata.FromHex(test.sig)}

		err := VerifySignature(test.pubKey, testdata.FromHex(test.in), signed)
		if test.errstr != "" {
			if err == nil {
				t.Errorf("VerifySignature(%s)=nil; want %q", test.in, test.errstr)
			} else if !strings.Contains(err.Error(), test.errstr) {
				t.Errorf("VerifySignature(%s)=%q; want %q", test.in, err.Error(), test.errstr)
			}
			continue
		}
		if err != nil {
			t.Errorf("VerifySignature(%s)=%q; want nil", test.in, err)
		}
	}
}

func TestCreateSignatureVerifySignatureRoundTrip(t *testing.T) {
	var tests = []struct {
		privKey  crypto.PrivateKey
		pubKey   crypto.PublicKey
		hashAlgo HashAlgorithm
	}{
		{PEM2PrivKey(testdata.RsaPrivateKeyPEM), PEM2PK(testdata.RsaPublicKeyPEM), SHA256},
		{PEM2PrivKey(testdata.EcdsaPrivateKeyPKCS8PEM), PEM2PK(testdata.EcdsaPublicKeyPEM), SHA256},
	}
	seed := time.Now().UnixNano()
	r := mathrand.New(mathrand.NewSource(seed))
	for _, test := range tests {
		for j := 0; j < 1; j++ {
			dataLen := 10 + r.Intn(100)
			data := make([]byte, dataLen)
			_, _ = r.Read(data)
			sig, err := CreateSignature(test.privKey, test.hashAlgo, data)
			if err != nil {
				t.Errorf("CreateSignature(%T, %v) failed with: %q", test.privKey, test.hashAlgo, err.Error())
				continue
			}

			if err := VerifySignature(test.pubKey, data, sig); err != nil {
				t.Errorf("VerifySignature(%T, %v) failed with: %q", test.pubKey, test.hashAlgo, err)
			}
		}
	}
}

func TestCreateSignatureFailures(t *testing.T) {
	var tests = []struct {
		privKey  crypto.PrivateKey
		hashAlgo HashAlgorithm
		in       string // hex encoded
		errstr   string
	}{
		{PEM2PrivKey(testdata.EcdsaPrivateKeyPKCS8PEM), 99, "abcd", "unsupported Algorithm.Hash"},
		{nil, SHA256, "abcd", "unsupported private key type"},
		// TODO(drysdale): the following test panics on Go < 1.7, so disable until the repo moves to 1.7
		// {*bogusKey, MD5, "abcd", "zero parameter"},
	}
	for _, test := range tests {
		if sig, err := CreateSignature(test.privKey, test.hashAlgo, testdata.FromHex(test.in)); err == nil {
			t.Errorf("CreateSignature(%T, %v)=%v,nil; want error %q", test.privKey, test.hashAlgo, sig, test.errstr)
		} else if !strings.Contains(err.Error(), test.errstr) {
			t.Errorf("CreateSignature(%T, %v)=nil,%q; want error %q", test.privKey, test.hashAlgo, err.Error(), test.errstr)
		}
	}
}

func PEM2PK(s string) crypto.PublicKey {
	p, _ := pem.Decode([]byte(s))
	if p == nil {
		panic("no PEM block found in " + s)
	}
	pubKey, _ := x509.ParsePKIXPublicKey(p.Bytes)
	if pubKey == nil {
		panic("public key not parsed from " + s)
	}
	return pubKey
}
func PEM2PrivKey(s string) crypto.PrivateKey {
	p, _ := pem.Decode([]byte(s))
	if p == nil {
		panic("no PEM block found in " + s)
	}

	// Try various different private key formats one after another.
	if rsaPrivKey, err := x509.ParsePKCS1PrivateKey(p.Bytes); err == nil {
		return *rsaPrivKey
	}
	if pkcs8Key, err := x509.ParsePKCS8PrivateKey(p.Bytes); err == nil {
		if reflect.TypeOf(pkcs8Key).Kind() == reflect.Ptr {
			pkcs8Key = reflect.ValueOf(pkcs8Key).Elem().Interface()
		}
		return pkcs8Key
	}

	return nil
}
func bogusKey() crypto.PrivateKey {
	bogusCurve := elliptic.P224()
	bogusCurve.Params().N.SetInt64(0)
	bogusKey, _ := ecdsa.GenerateKey(bogusCurve, rand.Reader)
	return *bogusKey
}
