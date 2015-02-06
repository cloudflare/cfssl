package revoke

import (
	"crypto/x509"
	//"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"testing"
	"time"
)

// The first three test cases represent known revoked, expired, and good
// certificates that were checked on the date listed in the log. The
// good certificate will eventually need to be replaced.

// If there is a soft-fail, the test will pass to mimic the default
// behaviour used in this software. However, it will print a warning
// to indicate that this is the case.

// 2014/05/22 14:18:17 Certificate expired 2014-04-04 14:14:20 +0000 UTC
// 2014/05/22 14:18:17 Revoked certificate: misc/intermediate_ca/ActalisServerAuthenticationCA.crt
var expiredCert = mustParse(`-----BEGIN CERTIFICATE-----
MIIEXTCCA8agAwIBAgIEBycURTANBgkqhkiG9w0BAQUFADB1MQswCQYDVQQGEwJV
UzEYMBYGA1UEChMPR1RFIENvcnBvcmF0aW9uMScwJQYDVQQLEx5HVEUgQ3liZXJU
cnVzdCBTb2x1dGlvbnMsIEluYy4xIzAhBgNVBAMTGkdURSBDeWJlclRydXN0IEds
b2JhbCBSb290MB4XDTA3MDQwNDE0MTUxNFoXDTE0MDQwNDE0MTQyMFowejELMAkG
A1UEBhMCSVQxFzAVBgNVBAoTDkFjdGFsaXMgUy5wLkEuMScwJQYDVQQLEx5DZXJ0
aWZpY2F0aW9uIFNlcnZpY2UgUHJvdmlkZXIxKTAnBgNVBAMTIEFjdGFsaXMgU2Vy
dmVyIEF1dGhlbnRpY2F0aW9uIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAv6P0bhXbUQkVW8ox0HJ+sP5+j6pTwS7yg/wGEUektB/G1duQiT1v21fo
LANr6F353jILQDCpHIfal3MhbSsHEMKU7XaqsyLWV93bcIKbIloS/eXDfkog6KB3
u0JHgrtNz584Jg/OLm9feffNbCJ38TiLo0/UWkAQ6PQWaOwZEgyKjVI5F3swoTB3
g0LZAzegvkU00Kfp13cSg+cJeU4SajwtfQ+g6s6dlaekaHy/0ef46PfiHHRuhEhE
JWIpDtUN2ywTT33MSSUe5glDIiXYfcamJQrebzGsHEwyqI195Yaxb+FLNND4n3HM
e7EI2OrLyT+r/WMvQbl+xNihwtv+HwIDAQABo4IBbzCCAWswEgYDVR0TAQH/BAgw
BgEB/wIBADBTBgNVHSAETDBKMEgGCSsGAQQBsT4BADA7MDkGCCsGAQUFBwIBFi1o
dHRwOi8vd3d3LnB1YmxpYy10cnVzdC5jb20vQ1BTL09tbmlSb290Lmh0bWwwDgYD
VR0PAQH/BAQDAgEGMIGJBgNVHSMEgYEwf6F5pHcwdTELMAkGA1UEBhMCVVMxGDAW
BgNVBAoTD0dURSBDb3Jwb3JhdGlvbjEnMCUGA1UECxMeR1RFIEN5YmVyVHJ1c3Qg
U29sdXRpb25zLCBJbmMuMSMwIQYDVQQDExpHVEUgQ3liZXJUcnVzdCBHbG9iYWwg
Um9vdIICAaUwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL3d3dy5wdWJsaWMtdHJ1
c3QuY29tL2NnaS1iaW4vQ1JMLzIwMTgvY2RwLmNybDAdBgNVHQ4EFgQUpi6OuXYt
oxHC3cTezVLuraWpAFEwDQYJKoZIhvcNAQEFBQADgYEAAtjJBwjsvw7DBs+v7BQz
gSGeg6nbYUuPL7+1driT5XsUKJ7WZjiwW2zW/WHZ+zGo1Ev8Dc574RpSrg/EIlfH
TpBiBuFgiKtJksKdoxPZGSI8FitwcgeW+y8wotmm0CtDzWN27g2kfSqHb5eHfZY5
sESPRwHkcMUNdAp37FLweUw=
-----END CERTIFICATE-----`)

// 2014/05/22 14:18:31 Serial number match: intermediate is revoked.
//	2014/05/22 14:18:31 certificate is revoked via CRL
// 2014/05/22 14:18:31 Revoked certificate: misc/intermediate_ca/MobileArmorEnterpriseCA.crt
var revokedCert = mustParse(`-----BEGIN CERTIFICATE-----
MIIEEzCCAvugAwIBAgILBAAAAAABGMGjftYwDQYJKoZIhvcNAQEFBQAwcTEoMCYG
A1UEAxMfR2xvYmFsU2lnbiBSb290U2lnbiBQYXJ0bmVycyBDQTEdMBsGA1UECxMU
Um9vdFNpZ24gUGFydG5lcnMgQ0ExGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
CzAJBgNVBAYTAkJFMB4XDTA4MDMxODEyMDAwMFoXDTE4MDMxODEyMDAwMFowJTEj
MCEGA1UEAxMaTW9iaWxlIEFybW9yIEVudGVycHJpc2UgQ0EwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQCaEjeDR73jSZVlacRn5bc5VIPdyouHvGIBUxyS
C6483HgoDlWrWlkEndUYFjRPiQqJFthdJxfglykXD+btHixMIYbz/6eb7hRTdT9w
HKsfH+wTBIdb5AZiNjkg3QcCET5HfanJhpREjZWP513jM/GSrG3VwD6X5yttCIH1
NFTDAr7aqpW/UPw4gcPfkwS92HPdIkb2DYnsqRrnKyNValVItkxJiotQ1HOO3YfX
ivGrHIbJdWYg0rZnkPOgYF0d+aIA4ZfwvdW48+r/cxvLevieuKj5CTBZZ8XrFt8r
JTZhZljbZvnvq/t6ZIzlwOj082f+lTssr1fJ3JsIPnG2lmgTAgMBAAGjgfcwgfQw
DgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwHQYDVR0OBBYEFIZw
ns4uzXdLX6xDRXUzFgZxWM7oME0GA1UdIARGMEQwQgYJKwYBBAGgMgE8MDUwMwYI
KwYBBQUHAgIwJxolaHR0cDovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5
LzA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8vY3JsLmdsb2JhbHNpZ24ubmV0L1Jv
b3RTaWduUGFydG5lcnMuY3JsMB8GA1UdIwQYMBaAFFaE7LVxpedj2NtRBNb65vBI
UknOMA0GCSqGSIb3DQEBBQUAA4IBAQBZvf+2xUJE0ekxuNk30kPDj+5u9oI3jZyM
wvhKcs7AuRAbcxPtSOnVGNYl8By7DPvPun+U3Yci8540y143RgD+kz3jxIBaoW/o
c4+X61v6DBUtcBPEt+KkV6HIsZ61SZmc/Y1I2eoeEt6JYoLjEZMDLLvc1cK/+wpg
dUZSK4O9kjvIXqvsqIOlkmh/6puSugTNao2A7EIQr8ut0ZmzKzMyZ0BuQhJDnAPd
Kz5vh+5tmytUPKA8hUgmLWe94lMb7Uqq2wgZKsqun5DAWleKu81w7wEcOrjiiB+x
jeBHq7OnpWm+ccTOPCE6H4ZN4wWVS7biEBUdop/8HgXBPQHWAdjL
-----END CERTIFICATE-----`)

// 2014/05/22 14:18:51 added misc/intermediate_ca/GandiProSSLCA.crt to intermediate bundle
var goodstring string = (`-----BEGIN CERTIFICATE-----
MIIEnjCCA4agAwIBAgIQPBkQvAZ54yVvTfQWo16zFDANBgkqhkiG9w0BAQUFADCB
lzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAlVUMRcwFQYDVQQHEw5TYWx0IExha2Ug
Q2l0eTEeMBwGA1UEChMVVGhlIFVTRVJUUlVTVCBOZXR3b3JrMSEwHwYDVQQLExho
dHRwOi8vd3d3LnVzZXJ0cnVzdC5jb20xHzAdBgNVBAMTFlVUTi1VU0VSRmlyc3Qt
SGFyZHdhcmUwHhcNMDgxMDIzMDAwMDAwWhcNMjAwNTMwMTA0ODM4WjA8MQswCQYD
VQQGEwJGUjESMBAGA1UEChMJR0FOREkgU0FTMRkwFwYDVQQDExBHYW5kaSBQcm8g
U1NMIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw5nFDd2ffWY4
OxZxUVj2uQ49ms1N68h471Kq5j3R9OkVJYwObJqozTZvnlcmJ/QG5lZY9+RXDNyU
V1EKVL92l4vHkngDhhTQaoIB0sNeJMdnCzzjebnmN3VTbSTniQhYEZPg1554Zo+2
U39kHBCPKZbwNk11EP4f7U7goyatkNJl0b28zEjbfGvJbPNE6vfaiBfM06spAHft
gJbCC2lzmv9L5R+KlixFFk3P8IkZInLnrGZ6iP0XIckVI8ENoMxu0SXb5JnfF8OS
QKdqBZKFBMbNJCCBQjXiv50hQEvVTX/INrqoMUfOVV1OT2HmuhPEBdoU0tU75mwm
VArKuQAdwwIDAQABo4IBPjCCATowHwYDVR0jBBgwFoAUoXJfJhsomEOVXQc31YWW
nUvSw0UwHQYDVR0OBBYEFMGxMoDxE5IUL21nMJIYqnw5VRQ+MA4GA1UdDwEB/wQE
AwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMBgGA1UdIAQRMA8wDQYLKwYBBAGyMQEC
AhowRAYDVR0fBD0wOzA5oDegNYYzaHR0cDovL2NybC51c2VydHJ1c3QuY29tL1VU
Ti1VU0VSRmlyc3QtSGFyZHdhcmUuY3JsMHQGCCsGAQUFBwEBBGgwZjA9BggrBgEF
BQcwAoYxaHR0cDovL2NydC51c2VydHJ1c3QuY29tL1VUTkFkZFRydXN0U2VydmVy
X0NBLmNydDAlBggrBgEFBQcwAYYZaHR0cDovL29jc3AudXNlcnRydXN0LmNvbTAN
BgkqhkiG9w0BAQUFAAOCAQEAjSvVDlj6cT/RDFCrOvqpd1gZD7rzKzDGpfi3IciU
cjatYny806bAaAxRqL56e3O4rRMr+Jw1sHGpcqfKkm3YBW0CyJAum4vI07lYjZpn
9ihcWeatDX4gp/6Pm862lGITpB6TLriX1G7EYdnjOudIajawz64vnyTdvzmC18BV
+wC3A9f57mnqzm5SghMSeGlF78y9vPUXWPfBx9JY4Ga/r+U59djQrgbKY93sgyXD
3LS+K6NqGCKt58LcXQq75/e0OnHoJ3tiPMiB1IuYoIRCXevitc1ynVyP/m5wuZqB
wHHiX3Eo2RFMBCfSE7mSUoSwgHWtp1tHh0IvL8H7dmKjZQ==
-----END CERTIFICATE-----`)

var goodCert = mustParse(goodstring)

func mustParse(pemData string) *x509.Certificate {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		panic("Invalid PEM data.")
	} else if block.Type != "CERTIFICATE" {
		panic("Invalid PEM type.")
	}

	cert, err := x509.ParseCertificate([]byte(block.Bytes))
	if err != nil {
		panic(err.Error())
	}
	return cert
}

func TestRevoked(t *testing.T) {
	if revoked, ok := VerifyCertificate(revokedCert); !ok {
		fmt.Fprintf(os.Stderr, "Warning: soft fail checking revocation")
	} else if !revoked {
		t.Fatalf("revoked certificate should have been marked as revoked")
	}
}

func TestExpired(t *testing.T) {
	if revoked, ok := VerifyCertificate(expiredCert); !ok {
		fmt.Fprintf(os.Stderr, "Warning: soft fail checking revocation")
	} else if !revoked {
		t.Fatalf("expired certificate should have been marked as revoked")
	}
}

func TestGood(t *testing.T) {
	if revoked, ok := VerifyCertificate(goodCert); !ok {
		fmt.Fprintf(os.Stderr, "Warning: soft fail checking revocation")
	} else if revoked {
		t.Fatalf("good certificate should not have been marked as revoked")
	}

}

func TestLdap(t *testing.T) {
	ldapCert := mustParse(goodstring)
	ldapCert.CRLDistributionPoints = append(ldapCert.CRLDistributionPoints, "ldap://myldap.example.com")
	if revoked, ok := VerifyCertificate(ldapCert); revoked || !ok {
		t.Fatalf("ldap certificate should have been recognized")
	}
}

func TestLdapURLErr(t *testing.T) {
	if ldapURL(":") {
		t.Fatalf("bad url does not cause error")
	}
}

func TestCertNotYetValid(t *testing.T) {
	notReadyCert := expiredCert
	notReadyCert.NotBefore = time.Date(3000, time.January, 1, 1, 1, 1, 1, time.Local)
	notReadyCert.NotAfter = time.Date(3005, time.January, 1, 1, 1, 1, 1, time.Local)
	if revoked, _ := VerifyCertificate(expiredCert); !revoked {
		t.Fatalf("not yet verified certificate should have been marked as revoked")
	}
}

func TestCRLFetchError(t *testing.T) {
	ldapCert := mustParse(goodstring)
	ldapCert.CRLDistributionPoints[0] = ""
	if revoked, ok := VerifyCertificate(ldapCert); ok || revoked {
		t.Fatalf("Fetching error not encountered")
	}
	HardFail = true
	if revoked, ok := VerifyCertificate(ldapCert); ok || !revoked {
		t.Fatalf("Fetching error not encountered, hardfail not registered")
	}
	HardFail = false
}

func TestBadCRLSet(t *testing.T) {
	ldapCert := mustParse(goodstring)
	ldapCert.CRLDistributionPoints[0] = ""
	CRLSet[""] = nil
	certIsRevokedCRL(ldapCert, "")
	if _, ok := CRLSet[""]; ok {
		t.Fatalf("key emptystring should be deleted from CRLSet")
	}
	delete(CRLSet, "")

}

func TestCachedCRLSet(t *testing.T) {
	VerifyCertificate(goodCert)
	if revoked, ok := VerifyCertificate(goodCert); !ok || revoked {
		t.Fatalf("Previously fetched CRL's should be read smoothly and unrevoked")
	}
}

func TestRemoteFetchError(t *testing.T) {

	badurl := ":"

	if _, err := fetchRemote(badurl); err == nil {
		t.Fatalf("fetching bad url should result in non-nil error")
	}

}

func TestNoOCSPServers(t *testing.T) {
	badIssuer := goodCert
	badIssuer.IssuingCertificateURL = []string{" "}
	certIsRevokedOCSP(badIssuer, true)
	noOCSPCert := goodCert
	noOCSPCert.OCSPServer = make([]string, 0)
	if revoked, ok := certIsRevokedOCSP(noOCSPCert, true); revoked || !ok {
		t.Fatalf("OCSP falsely registered as enabled for this certificate")
	}
}
