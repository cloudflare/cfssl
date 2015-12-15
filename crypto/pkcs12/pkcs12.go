// Package pkcs12 implements the parsing and encoding of key and certificate files into a PKCS#12 file
package pkcs12

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"

	"github.com/AGWA-forks/go-pkcs12"
)

// ParseAndEncode takes key, certificate, and optional password
// as []byte and parses them to get a suitable format to encode them
func ParseAndEncode(key, cert, password []byte) string {
	var file string
	certBlock, _ := pem.Decode(cert)
	certBytes := certBlock.Bytes
	certificate, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return file
	}

	block, _ := pem.Decode(key)
	privKey := block.Bytes
	if block.Type == "RSA PRIVATE KEY" {
		pkcsKey, err := x509.ParsePKCS1PrivateKey(privKey)
		if err != nil {
			return file
		}
		file = Encode(pkcsKey, certificate, password)
	} else if block.Type == "EC PRIVATE KEY" {
		ecKey, err := x509.ParseECPrivateKey(privKey)
		if err != nil {
			return file
		}
		file = Encode(ecKey, certificate, password)
	}

	return file
}

// Encode is called by ParseAndEncode with a key, certificate, and optional password
// to call AGWA-forks's pkcs12 encode function and returns the pkcs12 file as a base64 encoded string
func Encode(privateKey interface{}, certificate *x509.Certificate, password []byte) string {
	var none []*x509.Certificate
	var data string
	pfxData, err := pkcs12.Encode(privateKey, certificate, none, password)
	if err != nil {
		return data
	}

	data = base64.StdEncoding.EncodeToString(pfxData)

	return data
}
