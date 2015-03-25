// Package pkcs7 implements the subset of the CMS PKCS #7 datatype that is typically
// used to package certificates and CRLs.  Using openssl, every certificate converted
// to PKCS #7 format from another encoding such as PEM conforms to this implementation.
// reference: https://www.openssl.org/docs/apps/crl2pkcs7.html)
//
//			PKCS #7 Data type, reference: https://tools.ietf.org/html/rfc2315
//
// The full pkcs#7 cryptographic message syntax allows for cryptographic enhancements,
// for example data can be encrypted and signed and then packaged through pkcs#7 to be
// sent over a network and then verified and decrypted.  It is asn1, and the type of
// PKCS #7 ContentInfo, which comprises the PKCS #7 structure, is:
//
//			ContentInfo ::= SEQUENCE {
//				contentType ContentType,
//				content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
//			}
//
// There are 6 possible ContentTypes, data, signedData, envelopedData,
// signedAndEnvelopedData, digestedData, and encryptedData.  Here onlysignedData is
// implemented, as the degenerate case of signedData without a signature is the typical
// format for transferring certificates and CRLS. The ContentType signedData has the
// form:
//
//			signedData ::= SEQUENCE {
//				version Version,
//				digestAlgorithms DigestAlgorithmIdentifiers,
//				contentInfo ContentInfo,
//				certificates [0] IMPLICIT ExtendedCertificatesAndCertificates OPTIONAL
//				crls [1] IMPLICIT CertificateRevocationLists OPTIONAL,
//				signerInfos SignerInfos
//			}
//
// As of yet signerInfos and digestAlgorithms are not parsed, as they are not relevant to
// this system's use of PKCS #7 data.  Version is an integer type, note that PKCS #7 is
// recursive, this second layer of ContentInfo is similar ignored for our degenerate
// usage.  The ExtendedCertificatesAndCertificates type consists of a sequence of choices
// between PKCS #6 extended certificates andx509 certificates.  Any sequence consisting
// of any number of  extended certificates is not yet supported in this implementation
package pkcs7

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
)

// Types used for asn1 Unmarshaling

type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	ContentInfo      asn1.RawValue
	Certificates     asn1.RawValue `asn1:"optional" asn1:"tag:0"`
	Crls             asn1.RawValue `asn1:"optional"`
	SignerInfos      asn1.RawValue
}

type content struct {
	SignedData signedData
}

type initPKCS7 struct {
	Raw         asn1.RawContent
	ContentType asn1.ObjectIdentifier
	Content     content `asn1:"tag:0"`
}

// PKCS7 represents the ASN1 PKCS7 degenerate signedData content type
type PKCS7 struct {
	Raw          asn1.RawContent
	Version      int
	Certificates []*x509.Certificate
	Crl          *pkix.CertificateList
}

// ParsePKCS7 attempts to parse the DER encoded bytes of a
// PKCS7 structure
func ParsePKCS7(raw []byte) (msg *PKCS7, err error) {

	var pkcs7 initPKCS7
	_, err = asn1.Unmarshal(raw, &pkcs7)
	if err != nil {
		return nil, err
	}

	msg = new(PKCS7)
	msg.Raw = pkcs7.Raw
	msg.Version = pkcs7.Content.SignedData.Version

	if len(pkcs7.Content.SignedData.Certificates.Bytes) == 0 {
		msg.Certificates = nil
	} else {
		msg.Certificates, err = x509.ParseCertificates(pkcs7.Content.SignedData.Certificates.Bytes)
		if err != nil {
			return nil, err
		}
	}

	if len(pkcs7.Content.SignedData.Crls.Bytes) == 0 {
		msg.Crl = nil
	} else {
		msg.Crl, err = x509.ParseDERCRL(pkcs7.Content.SignedData.Crls.Bytes)
		if err != nil {
			return nil, err
		}
	}

	return msg, nil

}
