// Copyright 2016 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package x509util includes utility code for working with X.509
// certificates from the x509 package.
package x509util

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
)

// OIDForStandardExtension indicates whether oid identifies a standard extension.
// Standard extensions are listed in RFC 5280 (and other RFCs).
func OIDForStandardExtension(oid asn1.ObjectIdentifier) bool {
	if oid.Equal(x509.OIDExtensionSubjectKeyId) ||
		oid.Equal(x509.OIDExtensionKeyUsage) ||
		oid.Equal(x509.OIDExtensionExtendedKeyUsage) ||
		oid.Equal(x509.OIDExtensionAuthorityKeyId) ||
		oid.Equal(x509.OIDExtensionBasicConstraints) ||
		oid.Equal(x509.OIDExtensionSubjectAltName) ||
		oid.Equal(x509.OIDExtensionCertificatePolicies) ||
		oid.Equal(x509.OIDExtensionNameConstraints) ||
		oid.Equal(x509.OIDExtensionCRLDistributionPoints) ||
		oid.Equal(x509.OIDExtensionIssuerAltName) ||
		oid.Equal(x509.OIDExtensionSubjectDirectoryAttributes) ||
		oid.Equal(x509.OIDExtensionInhibitAnyPolicy) ||
		oid.Equal(x509.OIDExtensionPolicyConstraints) ||
		oid.Equal(x509.OIDExtensionPolicyMappings) ||
		oid.Equal(x509.OIDExtensionFreshestCRL) ||
		oid.Equal(x509.OIDExtensionSubjectInfoAccess) ||
		oid.Equal(x509.OIDExtensionAuthorityInfoAccess) ||
		oid.Equal(x509.OIDExtensionCTPoison) ||
		oid.Equal(x509.OIDExtensionCTSCT) {
		return true
	}
	return false
}

// OIDInExtensions checks whether the extension identified by oid is present in extensions
// and returns how many times it occurs together with an indication of whether any of them
// are marked critical.
func OIDInExtensions(oid asn1.ObjectIdentifier, extensions []pkix.Extension) (int, bool) {
	count := 0
	critical := false
	for _, ext := range extensions {
		if ext.Id.Equal(oid) {
			count++
			if ext.Critical {
				critical = true
			}
		}
	}
	return count, critical
}

// String formatting for various X.509/ASN.1 types
func bitStringToString(b asn1.BitString) string {
	result := hex.EncodeToString(b.Bytes)
	bitsLeft := b.BitLength % 8
	if bitsLeft != 0 {
		result += " (" + strconv.Itoa(8-bitsLeft) + " unused bits)"
	}
	return result
}

func publicKeyAlgorithmToString(algo x509.PublicKeyAlgorithm) string {
	// Use OpenSSL-compatible strings for the algorithms.
	switch algo {
	case x509.RSA:
		return "rsaEncryption"
	case x509.DSA:
		return "dsaEncryption"
	case x509.ECDSA:
		return "id-ecPublicKey"
	default:
		return strconv.Itoa(int(algo))
	}
}

// appendHexData adds a hex dump of binary data to buf, with line breaks
// after each set of count bytes, and with each new line prefixed with the
// given prefix.
func appendHexData(buf *bytes.Buffer, data []byte, count int, prefix string) {
	for ii, byte := range data {
		if ii%count == 0 {
			if ii > 0 {
				buf.WriteString("\n")
			}
			buf.WriteString(prefix)
		}
		buf.WriteString(fmt.Sprintf("%02x:", byte))
	}
}

func curveOIDToString(oid asn1.ObjectIdentifier) (t string, bitlen int) {
	switch {
	case oid.Equal(x509.OIDNamedCurveP224):
		return "secp224r1", 224
	case oid.Equal(x509.OIDNamedCurveP256):
		return "prime256v1", 256
	case oid.Equal(x509.OIDNamedCurveP384):
		return "secp384r1", 384
	case oid.Equal(x509.OIDNamedCurveP521):
		return "secp521r1", 521
	}
	return fmt.Sprintf("%v", oid), -1
}

func publicKeyToString(algo x509.PublicKeyAlgorithm, pub interface{}) string {
	var buf bytes.Buffer
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		bitlen := pub.N.BitLen()
		buf.WriteString(fmt.Sprintf("                Public Key: (%d bit)\n", bitlen))
		buf.WriteString("                Modulus:\n")
		data := pub.N.Bytes()
		appendHexData(&buf, data, 15, "                    ")
		buf.WriteString("\n")
		buf.WriteString(fmt.Sprintf("                Exponent: %d (0x%x)", pub.E, pub.E))
	case *dsa.PublicKey:
		buf.WriteString("                pub:\n")
		appendHexData(&buf, pub.Y.Bytes(), 15, "                    ")
		buf.WriteString("\n")
		buf.WriteString("                P:\n")
		appendHexData(&buf, pub.P.Bytes(), 15, "                    ")
		buf.WriteString("\n")
		buf.WriteString("                Q:\n")
		appendHexData(&buf, pub.Q.Bytes(), 15, "                    ")
		buf.WriteString("\n")
		buf.WriteString("                G:\n")
		appendHexData(&buf, pub.G.Bytes(), 15, "                    ")
	case *ecdsa.PublicKey:
		data := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
		oid, ok := x509.OIDFromNamedCurve(pub.Curve)
		if !ok {
			return "                <unsupported elliptic curve>"
		}
		oidname, bitlen := curveOIDToString(oid)
		buf.WriteString(fmt.Sprintf("                Public Key: (%d bit)\n", bitlen))
		buf.WriteString("                pub:\n")
		appendHexData(&buf, data, 15, "                    ")
		buf.WriteString("\n")
		buf.WriteString(fmt.Sprintf("                ASN1 OID: %s", oidname))
	default:
		buf.WriteString(fmt.Sprintf("%v", pub))
	}
	return buf.String()
}

func commaAppend(buf *bytes.Buffer, s string) {
	if buf.Len() > 0 {
		buf.WriteString(", ")
	}
	buf.WriteString(s)
}

func keyUsageToString(k x509.KeyUsage) string {
	var buf bytes.Buffer
	if k&x509.KeyUsageDigitalSignature != 0 {
		commaAppend(&buf, "Digital Signature")
	}
	if k&x509.KeyUsageContentCommitment != 0 {
		commaAppend(&buf, "Content Commitment")
	}
	if k&x509.KeyUsageKeyEncipherment != 0 {
		commaAppend(&buf, "Key Encipherment")
	}
	if k&x509.KeyUsageDataEncipherment != 0 {
		commaAppend(&buf, "Data Encipherment")
	}
	if k&x509.KeyUsageKeyAgreement != 0 {
		commaAppend(&buf, "Key Agreement")
	}
	if k&x509.KeyUsageCertSign != 0 {
		commaAppend(&buf, "Certificate Signing")
	}
	if k&x509.KeyUsageCRLSign != 0 {
		commaAppend(&buf, "CRL Signing")
	}
	if k&x509.KeyUsageEncipherOnly != 0 {
		commaAppend(&buf, "Encipher Only")
	}
	if k&x509.KeyUsageDecipherOnly != 0 {
		commaAppend(&buf, "Decipher Only")
	}
	return buf.String()
}

func extKeyUsageToString(u x509.ExtKeyUsage) string {
	switch u {
	case x509.ExtKeyUsageAny:
		return "Any"
	case x509.ExtKeyUsageServerAuth:
		return "TLS Web server authentication"
	case x509.ExtKeyUsageClientAuth:
		return "TLS Web client authentication"
	case x509.ExtKeyUsageCodeSigning:
		return "Signing of executable code"
	case x509.ExtKeyUsageEmailProtection:
		return "Email protection"
	case x509.ExtKeyUsageIPSECEndSystem:
		return "IPSEC end system"
	case x509.ExtKeyUsageIPSECTunnel:
		return "IPSEC tunnel"
	case x509.ExtKeyUsageIPSECUser:
		return "IPSEC user"
	case x509.ExtKeyUsageTimeStamping:
		return "Time stamping"
	case x509.ExtKeyUsageOCSPSigning:
		return "OCSP signing"
	case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
		return "Microsoft server gated cryptography"
	case x509.ExtKeyUsageNetscapeServerGatedCrypto:
		return "Netscape server gated cryptography"
	case x509.ExtKeyUsageCertificateTransparency:
		return "Certificate transparency"
	default:
		return "Unknown"
	}
}

func attributeOIDToString(oid asn1.ObjectIdentifier) string {
	switch {
	case oid.Equal(pkix.OIDCountry):
		return "Country"
	case oid.Equal(pkix.OIDOrganization):
		return "Organization"
	case oid.Equal(pkix.OIDOrganizationalUnit):
		return "OrganizationalUnit"
	case oid.Equal(pkix.OIDCommonName):
		return "CommonName"
	case oid.Equal(pkix.OIDSerialNumber):
		return "SerialNumber"
	case oid.Equal(pkix.OIDLocality):
		return "Locality"
	case oid.Equal(pkix.OIDProvince):
		return "Province"
	case oid.Equal(pkix.OIDStreetAddress):
		return "StreetAddress"
	case oid.Equal(pkix.OIDPostalCode):
		return "PostalCode"
	case oid.Equal(pkix.OIDPseudonym):
		return "Pseudonym"
	case oid.Equal(pkix.OIDTitle):
		return "Title"
	case oid.Equal(pkix.OIDDnQualifier):
		return "DnQualifier"
	case oid.Equal(pkix.OIDName):
		return "Name"
	case oid.Equal(pkix.OIDSurname):
		return "Surname"
	case oid.Equal(pkix.OIDGivenName):
		return "GivenName"
	case oid.Equal(pkix.OIDInitials):
		return "Initials"
	case oid.Equal(pkix.OIDGenerationQualifier):
		return "GenerationQualifier"
	default:
		return oid.String()
	}
}

// NameToString creates a string description of a pkix.Name object.
func NameToString(name pkix.Name) string {
	var result bytes.Buffer
	addSingle := func(prefix, item string) {
		if len(item) == 0 {
			return
		}
		commaAppend(&result, prefix)
		result.WriteString(item)
	}
	addList := func(prefix string, items []string) {
		for _, item := range items {
			addSingle(prefix, item)
		}
	}
	addList("C=", name.Country)
	addList("O=", name.Organization)
	addList("OU=", name.OrganizationalUnit)
	addList("L=", name.Locality)
	addList("ST=", name.Province)
	addList("streetAddress=", name.StreetAddress)
	addList("postalCode=", name.PostalCode)
	addSingle("serialNumber=", name.SerialNumber)
	addSingle("CN=", name.CommonName)
	for _, atv := range name.Names {
		value, ok := atv.Value.(string)
		if !ok {
			continue
		}
		t := atv.Type
		// All of the defined attribute OIDs are of the form 2.5.4.N, and OIDAttribute is
		// the 2.5.4 prefix ('id-at' in RFC 5280).
		if len(t) == 4 && t[0] == pkix.OIDAttribute[0] && t[1] == pkix.OIDAttribute[1] && t[2] == pkix.OIDAttribute[2] {
			// OID is 'id-at N', so check the final value to figure out which attribute.
			switch t[3] {
			case pkix.OIDCommonName[3], pkix.OIDSerialNumber[3], pkix.OIDCountry[3], pkix.OIDLocality[3], pkix.OIDProvince[3],
				pkix.OIDStreetAddress[3], pkix.OIDOrganization[3], pkix.OIDOrganizationalUnit[3], pkix.OIDPostalCode[3]:
				continue // covered by explicit fields
			case pkix.OIDPseudonym[3]:
				addSingle("pseudonym=", value)
				continue
			case pkix.OIDTitle[3]:
				addSingle("title=", value)
				continue
			case pkix.OIDDnQualifier[3]:
				addSingle("dnQualifier=", value)
				continue
			case pkix.OIDName[3]:
				addSingle("name=", value)
				continue
			case pkix.OIDSurname[3]:
				addSingle("surname=", value)
				continue
			case pkix.OIDGivenName[3]:
				addSingle("givenName=", value)
				continue
			case pkix.OIDInitials[3]:
				addSingle("initials=", value)
				continue
			case pkix.OIDGenerationQualifier[3]:
				addSingle("generationQualifier=", value)
				continue
			}
		}
		addSingle(t.String()+"=", value)
	}
	return result.String()
}

// OtherNameToString creates a string description of an x509.OtherName object.
func OtherNameToString(other x509.OtherName) string {
	return fmt.Sprintf("%v=%v", other.TypeID, hex.EncodeToString(other.Value.Bytes))
}

// GeneralNamesToString creates a string description of an x509.GeneralNames object.
func GeneralNamesToString(gname *x509.GeneralNames) string {
	var buf bytes.Buffer
	for _, name := range gname.DNSNames {
		commaAppend(&buf, "DNS:"+name)
	}
	for _, email := range gname.EmailAddresses {
		commaAppend(&buf, "email:"+email)
	}
	for _, name := range gname.DirectoryNames {
		commaAppend(&buf, "DirName:"+NameToString(name))
	}
	for _, uri := range gname.URIs {
		commaAppend(&buf, "URI:"+uri)
	}
	for _, ip := range gname.IPNets {
		if ip.Mask == nil {
			commaAppend(&buf, "IP Address:"+ip.IP.String())
		} else {
			commaAppend(&buf, "IP Address:"+ip.IP.String()+"/"+ip.Mask.String())
		}
	}
	for _, id := range gname.RegisteredIDs {
		commaAppend(&buf, "Registered ID:"+id.String())
	}
	for _, other := range gname.OtherNames {
		commaAppend(&buf, "othername:"+OtherNameToString(other))
	}
	return buf.String()
}

// CertificateToString generates a string describing the given certificate.
// The output roughly resembles that from openssl x509 -text.
func CertificateToString(cert *x509.Certificate) string {
	var result bytes.Buffer
	result.WriteString(fmt.Sprintf("Certificate:\n"))
	result.WriteString(fmt.Sprintf("    Data:\n"))
	result.WriteString(fmt.Sprintf("        Version: %d (%#x)\n", cert.Version, cert.Version-1))
	result.WriteString(fmt.Sprintf("        Serial Number: %d (%#[1]x)\n", cert.SerialNumber))
	result.WriteString(fmt.Sprintf("    Signature Algorithm: %v\n", cert.SignatureAlgorithm))
	result.WriteString(fmt.Sprintf("        Issuer: %v\n", NameToString(cert.Issuer)))
	result.WriteString(fmt.Sprintf("        Validity:\n"))
	result.WriteString(fmt.Sprintf("            Not Before: %v\n", cert.NotBefore))
	result.WriteString(fmt.Sprintf("            Not After : %v\n", cert.NotAfter))
	result.WriteString(fmt.Sprintf("        Subject: %v\n", NameToString(cert.Subject)))
	result.WriteString(fmt.Sprintf("        Subject Public Key Info:\n"))
	result.WriteString(fmt.Sprintf("            Public Key Algorithm: %v\n", publicKeyAlgorithmToString(cert.PublicKeyAlgorithm)))
	result.WriteString(fmt.Sprintf("%v\n", publicKeyToString(cert.PublicKeyAlgorithm, cert.PublicKey)))

	if len(cert.Extensions) > 0 {
		result.WriteString(fmt.Sprintf("        X509v3 extensions:\n"))
	}
	// First display the extensions that are already cracked out
	showAuthKeyID(&result, cert)
	showSubjectKeyID(&result, cert)
	showKeyUsage(&result, cert)
	showExtendedKeyUsage(&result, cert)
	showBasicConstraints(&result, cert)
	showSubjectAltName(&result, cert)
	showNameConstraints(&result, cert)
	showCertPolicies(&result, cert)
	showCRLDPs(&result, cert)
	showAuthInfoAccess(&result, cert)
	showCTPoison(&result, cert)
	showCTSCT(&result, cert)

	showUnhandledExtensions(&result, cert)
	showSignature(&result, cert)

	return result.String()
}

func showCritical(result *bytes.Buffer, critical bool) {
	if critical {
		result.WriteString(" critical")
	}
	result.WriteString("\n")
}

func showAuthKeyID(result *bytes.Buffer, cert *x509.Certificate) {
	count, critical := OIDInExtensions(x509.OIDExtensionAuthorityKeyId, cert.Extensions)
	if count > 0 {
		result.WriteString(fmt.Sprintf("            X509v3 Authority Key Identifier:"))
		showCritical(result, critical)
		result.WriteString(fmt.Sprintf("                keyid:%v\n", hex.EncodeToString(cert.AuthorityKeyId)))
	}
}

func showSubjectKeyID(result *bytes.Buffer, cert *x509.Certificate) {
	count, critical := OIDInExtensions(x509.OIDExtensionSubjectKeyId, cert.Extensions)
	if count > 0 {
		result.WriteString(fmt.Sprintf("            X509v3 Subject Key Identifier:"))
		showCritical(result, critical)
		result.WriteString(fmt.Sprintf("                keyid:%v\n", hex.EncodeToString(cert.SubjectKeyId)))
	}
}

func showKeyUsage(result *bytes.Buffer, cert *x509.Certificate) {
	count, critical := OIDInExtensions(x509.OIDExtensionKeyUsage, cert.Extensions)
	if count > 0 {
		result.WriteString(fmt.Sprintf("            X509v3 Key Usage:"))
		showCritical(result, critical)
		result.WriteString(fmt.Sprintf("                %v\n", keyUsageToString(cert.KeyUsage)))
	}
}

func showExtendedKeyUsage(result *bytes.Buffer, cert *x509.Certificate) {
	count, critical := OIDInExtensions(x509.OIDExtensionExtendedKeyUsage, cert.Extensions)
	if count > 0 {
		result.WriteString(fmt.Sprintf("            X509v3 Extended Key Usage:"))
		showCritical(result, critical)
		var usages bytes.Buffer
		for _, usage := range cert.ExtKeyUsage {
			commaAppend(&usages, extKeyUsageToString(usage))
		}
		for _, oid := range cert.UnknownExtKeyUsage {
			commaAppend(&usages, oid.String())
		}
		result.WriteString(fmt.Sprintf("                %v\n", usages.String()))
	}
}

func showBasicConstraints(result *bytes.Buffer, cert *x509.Certificate) {
	count, critical := OIDInExtensions(x509.OIDExtensionBasicConstraints, cert.Extensions)
	if count > 0 {
		result.WriteString(fmt.Sprintf("            X509v3 Basic Constraints:"))
		showCritical(result, critical)
		result.WriteString(fmt.Sprintf("                CA:%t", cert.IsCA))
		if cert.MaxPathLen > 0 || cert.MaxPathLenZero {
			result.WriteString(fmt.Sprintf(", pathlen:%d", cert.MaxPathLen))
		}
		result.WriteString(fmt.Sprintf("\n"))
	}
}

func showSubjectAltName(result *bytes.Buffer, cert *x509.Certificate) {
	count, critical := OIDInExtensions(x509.OIDExtensionSubjectAltName, cert.Extensions)
	if count > 0 {
		result.WriteString(fmt.Sprintf("            X509v3 Subject Alternative Name:"))
		showCritical(result, critical)
		var buf bytes.Buffer
		for _, name := range cert.DNSNames {
			commaAppend(&buf, "DNS:"+name)
		}
		for _, email := range cert.EmailAddresses {
			commaAppend(&buf, "email:"+email)
		}
		for _, ip := range cert.IPAddresses {
			commaAppend(&buf, "IP Address:"+ip.String())
		}

		result.WriteString(fmt.Sprintf("                %v\n", buf.String()))
		// TODO(drysdale): include other name forms
	}
}

func showNameConstraints(result *bytes.Buffer, cert *x509.Certificate) {
	count, critical := OIDInExtensions(x509.OIDExtensionNameConstraints, cert.Extensions)
	if count > 0 {
		result.WriteString(fmt.Sprintf("            X509v3 Name Constraints:"))
		showCritical(result, critical)
		if len(cert.PermittedDNSDomains) > 0 {
			result.WriteString(fmt.Sprintf("                Permitted:\n"))
			var buf bytes.Buffer
			for _, name := range cert.PermittedDNSDomains {
				commaAppend(&buf, "DNS:"+name)
			}
			result.WriteString(fmt.Sprintf("                  %v\n", buf.String()))
		}
		// TODO(drysdale): include other name forms
	}

}

func showCertPolicies(result *bytes.Buffer, cert *x509.Certificate) {
	count, critical := OIDInExtensions(x509.OIDExtensionCertificatePolicies, cert.Extensions)
	if count > 0 {
		result.WriteString(fmt.Sprintf("            X509v3 Certificate Policies:"))
		showCritical(result, critical)
		for _, oid := range cert.PolicyIdentifiers {
			result.WriteString(fmt.Sprintf("                Policy: %v\n", oid.String()))
			// TODO(drysdale): Display any qualifiers associated with the policy
		}
	}

}

func showCRLDPs(result *bytes.Buffer, cert *x509.Certificate) {
	count, critical := OIDInExtensions(x509.OIDExtensionCRLDistributionPoints, cert.Extensions)
	if count > 0 {
		result.WriteString(fmt.Sprintf("            X509v3 CRL Distribution Points:"))
		showCritical(result, critical)
		result.WriteString(fmt.Sprintf("                Full Name:\n"))
		var buf bytes.Buffer
		for _, pt := range cert.CRLDistributionPoints {
			commaAppend(&buf, "URI:"+pt)
		}
		result.WriteString(fmt.Sprintf("                    %v\n", buf.String()))
		// TODO(drysdale): Display other GeneralNames types, plus issuer/reasons/relative-name
	}

}

func showAuthInfoAccess(result *bytes.Buffer, cert *x509.Certificate) {
	count, critical := OIDInExtensions(x509.OIDExtensionAuthorityInfoAccess, cert.Extensions)
	if count > 0 {
		result.WriteString(fmt.Sprintf("            Authority Information Access:"))
		showCritical(result, critical)
		var issuerBuf bytes.Buffer
		for _, issuer := range cert.IssuingCertificateURL {
			commaAppend(&issuerBuf, "URI:"+issuer)
		}
		if issuerBuf.Len() > 0 {
			result.WriteString(fmt.Sprintf("                CA Issuers - %v\n", issuerBuf.String()))
		}
		var ocspBuf bytes.Buffer
		for _, ocsp := range cert.OCSPServer {
			commaAppend(&ocspBuf, "URI:"+ocsp)
		}
		if ocspBuf.Len() > 0 {
			result.WriteString(fmt.Sprintf("                OCSP - %v\n", ocspBuf.String()))
		}
		// TODO(drysdale): Display other GeneralNames types
	}
}

func showCTPoison(result *bytes.Buffer, cert *x509.Certificate) {
	count, critical := OIDInExtensions(x509.OIDExtensionCTPoison, cert.Extensions)
	if count > 0 {
		result.WriteString(fmt.Sprintf("            RFC6962 Pre-Certificate Poison:"))
		showCritical(result, critical)
		result.WriteString("                .....\n")
	}
}

func showCTSCT(result *bytes.Buffer, cert *x509.Certificate) {
	count, critical := OIDInExtensions(x509.OIDExtensionCTSCT, cert.Extensions)
	if count > 0 {
		result.WriteString(fmt.Sprintf("            RFC6962 Certificate Transparency SCT:"))
		showCritical(result, critical)
		for i, sctData := range cert.SCTList.SCTList {
			result.WriteString(fmt.Sprintf("              SCT [%d]:\n", i))
			var sct ct.SignedCertificateTimestamp
			_, err := tls.Unmarshal(sctData.Val, &sct)
			if err != nil {
				appendHexData(result, sctData.Val, 16, "                  ")
				result.WriteString("\n")
				continue
			}
			result.WriteString(fmt.Sprintf("                  Version: %d\n", sct.SCTVersion))
			result.WriteString(fmt.Sprintf("                  LogID: %s\n", base64.StdEncoding.EncodeToString(sct.LogID.KeyID[:])))
			result.WriteString(fmt.Sprintf("                  Timestamp: %d\n", sct.Timestamp))
			result.WriteString(fmt.Sprintf("                  Signature: %s\n", sct.Signature.Algorithm))
			result.WriteString(fmt.Sprintf("                  Signature:\n"))
			appendHexData(result, sct.Signature.Signature, 16, "                    ")
			result.WriteString("\n")
		}
	}
}

func showUnhandledExtensions(result *bytes.Buffer, cert *x509.Certificate) {
	for _, ext := range cert.Extensions {
		// Skip extensions that are already cracked out
		if oidAlreadyPrinted(ext.Id) {
			continue
		}
		result.WriteString(fmt.Sprintf("            %v:", ext.Id))
		showCritical(result, ext.Critical)
		appendHexData(result, ext.Value, 16, "                ")
		result.WriteString("\n")
	}
}

func showSignature(result *bytes.Buffer, cert *x509.Certificate) {
	result.WriteString(fmt.Sprintf("    Signature Algorithm: %v\n", cert.SignatureAlgorithm))
	appendHexData(result, cert.Signature, 18, "         ")
	result.WriteString("\n")
}

// TODO(drysdale): remove this once all standard OIDs are parsed and printed.
func oidAlreadyPrinted(oid asn1.ObjectIdentifier) bool {
	if oid.Equal(x509.OIDExtensionSubjectKeyId) ||
		oid.Equal(x509.OIDExtensionKeyUsage) ||
		oid.Equal(x509.OIDExtensionExtendedKeyUsage) ||
		oid.Equal(x509.OIDExtensionAuthorityKeyId) ||
		oid.Equal(x509.OIDExtensionBasicConstraints) ||
		oid.Equal(x509.OIDExtensionSubjectAltName) ||
		oid.Equal(x509.OIDExtensionCertificatePolicies) ||
		oid.Equal(x509.OIDExtensionNameConstraints) ||
		oid.Equal(x509.OIDExtensionCRLDistributionPoints) ||
		oid.Equal(x509.OIDExtensionAuthorityInfoAccess) ||
		oid.Equal(x509.OIDExtensionCTPoison) ||
		oid.Equal(x509.OIDExtensionCTSCT) {
		return true
	}
	return false
}

// CertificateFromPEM takes a string representing a certificate in PEM format
// and returns the corresponding x509.Certificate object.
func CertificateFromPEM(pemBytes string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemBytes))
	if block == nil {
		return nil, errors.New("failed to decode PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}
