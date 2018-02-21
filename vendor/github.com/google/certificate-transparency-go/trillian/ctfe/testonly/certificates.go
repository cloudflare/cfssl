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

package testonly

// UnknownBlockTypePEM is a PEM containing only an empty block of a non standard type
const UnknownBlockTypePEM string = `
-----BEGIN SOMETHING-----
-----END SOMETHING-----
`

// CACertPEMWithOtherStuff is a valid test CA certificate (CACertPEM below) with additional blocks
// surrounding it.
const CACertPEMWithOtherStuff string = `
-----BEGIN SOMETHING-----
-----END SOMETHING-----
-----BEGIN CERTIFICATE-----
MIIC0DCCAjmgAwIBAgIBADANBgkqhkiG9w0BAQUFADBVMQswCQYDVQQGEwJHQjEk
MCIGA1UEChMbQ2VydGlmaWNhdGUgVHJhbnNwYXJlbmN5IENBMQ4wDAYDVQQIEwVX
YWxlczEQMA4GA1UEBxMHRXJ3IFdlbjAeFw0xMjA2MDEwMDAwMDBaFw0yMjA2MDEw
MDAwMDBaMFUxCzAJBgNVBAYTAkdCMSQwIgYDVQQKExtDZXJ0aWZpY2F0ZSBUcmFu
c3BhcmVuY3kgQ0ExDjAMBgNVBAgTBVdhbGVzMRAwDgYDVQQHEwdFcncgV2VuMIGf
MA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDVimhTYhCicRmTbneDIRgcKkATxtB7
jHbrkVfT0PtLO1FuzsvRyY2RxS90P6tjXVUJnNE6uvMa5UFEJFGnTHgW8iQ8+EjP
KDHM5nugSlojgZ88ujfmJNnDvbKZuDnd/iYx0ss6hPx7srXFL8/BT/9Ab1zURmnL
svfP34b7arnRsQIDAQABo4GvMIGsMB0GA1UdDgQWBBRfnYgNyHPmVNT4DdjmsMEk
tEfDVTB9BgNVHSMEdjB0gBRfnYgNyHPmVNT4DdjmsMEktEfDVaFZpFcwVTELMAkG
A1UEBhMCR0IxJDAiBgNVBAoTG0NlcnRpZmljYXRlIFRyYW5zcGFyZW5jeSBDQTEO
MAwGA1UECBMFV2FsZXMxEDAOBgNVBAcTB0VydyBXZW6CAQAwDAYDVR0TBAUwAwEB
/zANBgkqhkiG9w0BAQUFAAOBgQAGCMxKbWTyIF4UbASydvkrDvqUpdryOvw4BmBt
OZDQoeojPUApV2lGOwRmYef6HReZFSCa6i4Kd1F2QRIn18ADB8dHDmFYT9czQiRy
f1HWkLxHqd81TbD26yWVXeGJPE3VICskovPkQNJ0tU4b03YmnKliibduyqQQkOFP
OwqULg==
-----END CERTIFICATE-----
-----BEGIN SOMETHING-----
-----END SOMETHING-----
`

// CACertPEM is a valid test CA certificate:
//   Data:
//       Version: 3 (0x2)
//       Serial Number: 0 (0x0)
//   Signature Algorithm: sha1WithRSAEncryption
//       Issuer: C=GB, O=Certificate Transparency CA, ST=Wales, L=Erw Wen
//       Validity
//           Not Before: Jun  1 00:00:00 2012 GMT
//           Not After : Jun  1 00:00:00 2022 GMT
//       Subject: C=GB, O=Certificate Transparency CA, ST=Wales, L=Erw Wen
//       Subject Public Key Info:
//           Public Key Algorithm: rsaEncryption
//               Public-Key: (1024 bit)
//               Modulus:
//                   00:d5:8a:68:53:62:10:a2:71:19:93:6e:77:83:21:
//                   18:1c:2a:40:13:c6:d0:7b:8c:76:eb:91:57:d3:d0:
//                   fb:4b:3b:51:6e:ce:cb:d1:c9:8d:91:c5:2f:74:3f:
//                   ab:63:5d:55:09:9c:d1:3a:ba:f3:1a:e5:41:44:24:
//                   51:a7:4c:78:16:f2:24:3c:f8:48:cf:28:31:cc:e6:
//                   7b:a0:4a:5a:23:81:9f:3c:ba:37:e6:24:d9:c3:bd:
//                   b2:99:b8:39:dd:fe:26:31:d2:cb:3a:84:fc:7b:b2:
//                   b5:c5:2f:cf:c1:4f:ff:40:6f:5c:d4:46:69:cb:b2:
//                   f7:cf:df:86:fb:6a:b9:d1:b1
//               Exponent: 65537 (0x10001)
//       X509v3 extensions:
//           X509v3 Subject Key Identifier:
//               5F:9D:88:0D:C8:73:E6:54:D4:F8:0D:D8:E6:B0:C1:24:B4:47:C3:55
//           X509v3 Authority Key Identifier:
//               keyid:5F:9D:88:0D:C8:73:E6:54:D4:F8:0D:D8:E6:B0:C1:24:B4:47:C3:55
//               DirName:/C=GB/O=Certificate Transparency CA/ST=Wales/L=Erw Wen
//               serial:00
//
//           X509v3 Basic Constraints:
//               CA:TRUE
//   Signature Algorithm: sha1WithRSAEncryption
//        06:08:cc:4a:6d:64:f2:20:5e:14:6c:04:b2:76:f9:2b:0e:fa:
//        94:a5:da:f2:3a:fc:38:06:60:6d:39:90:d0:a1:ea:23:3d:40:
//        29:57:69:46:3b:04:66:61:e7:fa:1d:17:99:15:20:9a:ea:2e:
//        0a:77:51:76:41:12:27:d7:c0:03:07:c7:47:0e:61:58:4f:d7:
//        33:42:24:72:7f:51:d6:90:bc:47:a9:df:35:4d:b0:f6:eb:25:
//        95:5d:e1:89:3c:4d:d5:20:2b:24:a2:f3:e4:40:d2:74:b5:4e:
//        1b:d3:76:26:9c:a9:62:89:b7:6e:ca:a4:10:90:e1:4f:3b:0a:
//        94:2e
const CACertPEM string = `
-----BEGIN CERTIFICATE-----
MIIC0DCCAjmgAwIBAgIBADANBgkqhkiG9w0BAQUFADBVMQswCQYDVQQGEwJHQjEk
MCIGA1UEChMbQ2VydGlmaWNhdGUgVHJhbnNwYXJlbmN5IENBMQ4wDAYDVQQIEwVX
YWxlczEQMA4GA1UEBxMHRXJ3IFdlbjAeFw0xMjA2MDEwMDAwMDBaFw0yMjA2MDEw
MDAwMDBaMFUxCzAJBgNVBAYTAkdCMSQwIgYDVQQKExtDZXJ0aWZpY2F0ZSBUcmFu
c3BhcmVuY3kgQ0ExDjAMBgNVBAgTBVdhbGVzMRAwDgYDVQQHEwdFcncgV2VuMIGf
MA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDVimhTYhCicRmTbneDIRgcKkATxtB7
jHbrkVfT0PtLO1FuzsvRyY2RxS90P6tjXVUJnNE6uvMa5UFEJFGnTHgW8iQ8+EjP
KDHM5nugSlojgZ88ujfmJNnDvbKZuDnd/iYx0ss6hPx7srXFL8/BT/9Ab1zURmnL
svfP34b7arnRsQIDAQABo4GvMIGsMB0GA1UdDgQWBBRfnYgNyHPmVNT4DdjmsMEk
tEfDVTB9BgNVHSMEdjB0gBRfnYgNyHPmVNT4DdjmsMEktEfDVaFZpFcwVTELMAkG
A1UEBhMCR0IxJDAiBgNVBAoTG0NlcnRpZmljYXRlIFRyYW5zcGFyZW5jeSBDQTEO
MAwGA1UECBMFV2FsZXMxEDAOBgNVBAcTB0VydyBXZW6CAQAwDAYDVR0TBAUwAwEB
/zANBgkqhkiG9w0BAQUFAAOBgQAGCMxKbWTyIF4UbASydvkrDvqUpdryOvw4BmBt
OZDQoeojPUApV2lGOwRmYef6HReZFSCa6i4Kd1F2QRIn18ADB8dHDmFYT9czQiRy
f1HWkLxHqd81TbD26yWVXeGJPE3VICskovPkQNJ0tU4b03YmnKliibduyqQQkOFP
OwqULg==
-----END CERTIFICATE-----
`

// CACertPEMDuplicated contains two identical copies of the same test CA certificate
const CACertPEMDuplicated string = `
-----BEGIN CERTIFICATE-----
MIIC0DCCAjmgAwIBAgIBADANBgkqhkiG9w0BAQUFADBVMQswCQYDVQQGEwJHQjEk
MCIGA1UEChMbQ2VydGlmaWNhdGUgVHJhbnNwYXJlbmN5IENBMQ4wDAYDVQQIEwVX
YWxlczEQMA4GA1UEBxMHRXJ3IFdlbjAeFw0xMjA2MDEwMDAwMDBaFw0yMjA2MDEw
MDAwMDBaMFUxCzAJBgNVBAYTAkdCMSQwIgYDVQQKExtDZXJ0aWZpY2F0ZSBUcmFu
c3BhcmVuY3kgQ0ExDjAMBgNVBAgTBVdhbGVzMRAwDgYDVQQHEwdFcncgV2VuMIGf
MA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDVimhTYhCicRmTbneDIRgcKkATxtB7
jHbrkVfT0PtLO1FuzsvRyY2RxS90P6tjXVUJnNE6uvMa5UFEJFGnTHgW8iQ8+EjP
KDHM5nugSlojgZ88ujfmJNnDvbKZuDnd/iYx0ss6hPx7srXFL8/BT/9Ab1zURmnL
svfP34b7arnRsQIDAQABo4GvMIGsMB0GA1UdDgQWBBRfnYgNyHPmVNT4DdjmsMEk
tEfDVTB9BgNVHSMEdjB0gBRfnYgNyHPmVNT4DdjmsMEktEfDVaFZpFcwVTELMAkG
A1UEBhMCR0IxJDAiBgNVBAoTG0NlcnRpZmljYXRlIFRyYW5zcGFyZW5jeSBDQTEO
MAwGA1UECBMFV2FsZXMxEDAOBgNVBAcTB0VydyBXZW6CAQAwDAYDVR0TBAUwAwEB
/zANBgkqhkiG9w0BAQUFAAOBgQAGCMxKbWTyIF4UbASydvkrDvqUpdryOvw4BmBt
OZDQoeojPUApV2lGOwRmYef6HReZFSCa6i4Kd1F2QRIn18ADB8dHDmFYT9czQiRy
f1HWkLxHqd81TbD26yWVXeGJPE3VICskovPkQNJ0tU4b03YmnKliibduyqQQkOFP
OwqULg==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIC0DCCAjmgAwIBAgIBADANBgkqhkiG9w0BAQUFADBVMQswCQYDVQQGEwJHQjEk
MCIGA1UEChMbQ2VydGlmaWNhdGUgVHJhbnNwYXJlbmN5IENBMQ4wDAYDVQQIEwVX
YWxlczEQMA4GA1UEBxMHRXJ3IFdlbjAeFw0xMjA2MDEwMDAwMDBaFw0yMjA2MDEw
MDAwMDBaMFUxCzAJBgNVBAYTAkdCMSQwIgYDVQQKExtDZXJ0aWZpY2F0ZSBUcmFu
c3BhcmVuY3kgQ0ExDjAMBgNVBAgTBVdhbGVzMRAwDgYDVQQHEwdFcncgV2VuMIGf
MA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDVimhTYhCicRmTbneDIRgcKkATxtB7
jHbrkVfT0PtLO1FuzsvRyY2RxS90P6tjXVUJnNE6uvMa5UFEJFGnTHgW8iQ8+EjP
KDHM5nugSlojgZ88ujfmJNnDvbKZuDnd/iYx0ss6hPx7srXFL8/BT/9Ab1zURmnL
svfP34b7arnRsQIDAQABo4GvMIGsMB0GA1UdDgQWBBRfnYgNyHPmVNT4DdjmsMEk
tEfDVTB9BgNVHSMEdjB0gBRfnYgNyHPmVNT4DdjmsMEktEfDVaFZpFcwVTELMAkG
A1UEBhMCR0IxJDAiBgNVBAoTG0NlcnRpZmljYXRlIFRyYW5zcGFyZW5jeSBDQTEO
MAwGA1UECBMFV2FsZXMxEDAOBgNVBAcTB0VydyBXZW6CAQAwDAYDVR0TBAUwAwEB
/zANBgkqhkiG9w0BAQUFAAOBgQAGCMxKbWTyIF4UbASydvkrDvqUpdryOvw4BmBt
OZDQoeojPUApV2lGOwRmYef6HReZFSCa6i4Kd1F2QRIn18ADB8dHDmFYT9czQiRy
f1HWkLxHqd81TbD26yWVXeGJPE3VICskovPkQNJ0tU4b03YmnKliibduyqQQkOFP
OwqULg==
-----END CERTIFICATE-----
`

// CACertPEMBad is a PEM block that contains invalid data that should not decode
const CACertPEMBad string = `
-----BEGIN CERTIFICATE-----
MIIC0DCCAjmgAwIBAgIBADANBgkqhkiG9w0BAQUFADBVMQswCQYDVQQGEwJHQjEk
MCIGA1UEChMbQ2VydGlmaWNhdGUgVHJhbnNwYXJlbmN5IENBMQ4wDAYDVQQIEwVX
YWxlczEQMA4GA1UEBxMHRXJ3IFdlbjAeFw0xMjA2MDEwMDAwMDBaFw0yMjA2MDEw
MDAwMDBaMFUxCzAJBgNVBAYTAkdCMSQwIgYDVQQKExtDZXJ0aWZpY2F0ZSBUcmFu
c3BhcmVuY3kgQ0ExDjAMBgNVBAgTBVdhbGVzMRAwDgYDVQQHEwdFcncgV2VuMIGf
MA0GCSqGSIb3DQEBA!"£$%^&&**SDFSKJ$%%^%^%^%&^&^!"£$%%IRgcKkATxtB7
jHbrkVfT0PtLO1FuzsvRyY2RxS90P6tjXVUJnNE6uvMa5UFEJFGnTHgW8iQ8+EjP
KDHM5nugSlojgZ88ujfmJNnDvbKZuDnd/iYx0ss6hPx7srXFL8/BT/9Ab1zURmnL
svfP34b7arnRsQIDAQABo4GvMIGsMB0GA1UdDgQWBBRfnYgNyHPmVNT4DdjmsMEk
tEfDVTB9BgNVHSMEdjB0gBRfnYgNyHPmVNT4DdjmsMEktEfDVaFZpFcwVTELMAkG
A1UEBhMCR0IxJDAiBgNVBAoTG0NlcnRpZmljYXRlIFRyYW5zcGFyZW5jeSBDQTEO
MAwGA1UECBMFV2FsZXMxEDAOBgNVBAcTB0VydyBXZW6CAQAwDAYDVR0TBAUwAwEB
/zANBgkqhkiG9w0BAQUFAAOBgQAGCMxKbWTyIF4UbASydvkrDvqUpdryOvw4BmBt
OZDQoeojPUApV2lGOwRmYef6HReZFSCa6i4Kd1F2QRIn18ADB8dHDmFYT9czQiRy
f1HWkLxHqd81TbD26yWVXeGJPE3VICskovPkQNJ0tU4b03YmnKliibduyqQQkOFP
OwqULg==
-----END CERTIFICATE-----
`

// CACertMultiplePEM is a PEM block containing a valid CA and intermediate certificate,
// specifically CACertPEM above and then:
//   Data:
//       Version: 3 (0x2)
//       Serial Number: 9 (0x9)
//   Signature Algorithm: sha1WithRSAEncryption
//       Issuer: C=GB, O=Certificate Transparency CA, ST=Wales, L=Erw Wen
//       Validity
//           Not Before: Jun  1 00:00:00 2012 GMT
//           Not After : Jun  1 00:00:00 2022 GMT
//       Subject: C=GB, O=Certificate Transparency Intermediate CA, ST=Wales, L=Erw Wen
//       Subject Public Key Info:
//           Public Key Algorithm: rsaEncryption
//               Public-Key: (1024 bit)
//               Modulus:
//                   00:d7:6a:67:8d:11:6f:52:2e:55:ff:82:1c:90:64:
//                   25:08:b7:07:4b:14:d7:71:15:90:64:f7:92:7e:fd:
//                   ed:b8:71:35:a1:36:5e:e7:de:18:cb:d5:ce:86:5f:
//                   86:0c:78:f4:33:b4:d0:d3:d3:40:77:02:e7:a3:ef:
//                   54:2b:1d:fe:9b:ba:a7:cd:f9:4d:c5:97:5f:c7:29:
//                   f8:6f:10:5f:38:1b:24:35:35:cf:9c:80:0f:5c:a7:
//                   80:c1:d3:c8:44:00:ee:65:d1:6e:e9:cf:52:db:8a:
//                   df:fe:50:f5:c4:93:35:0b:21:90:bf:50:d5:bc:36:
//                   f3:ca:c5:a8:da:ae:92:cd:8b
//               Exponent: 65537 (0x10001)
//       X509v3 extensions:
//           X509v3 Subject Key Identifier:
//               96:55:08:05:02:78:47:9E:87:73:76:41:31:BC:14:3A:47:E2:29:AB
//           X509v3 Authority Key Identifier:
//               keyid:5F:9D:88:0D:C8:73:E6:54:D4:F8:0D:D8:E6:B0:C1:24:B4:47:C3:55
//               DirName:/C=GB/O=Certificate Transparency CA/ST=Wales/L=Erw Wen
//               serial:00
//
//           X509v3 Basic Constraints:
//               CA:TRUE
//   Signature Algorithm: sha1WithRSAEncryption
//        22:06:da:b1:c6:6b:71:dc:e0:95:c3:f6:aa:2e:f7:2c:f7:76:
//        1b:e7:ab:d7:fc:39:c3:1a:4c:fe:1b:d9:6d:67:34:ca:82:f2:
//        2d:de:5a:0c:8b:bb:dd:82:5d:7b:6f:3e:76:12:ad:8d:b3:00:
//        a7:e2:11:69:88:60:23:26:22:84:c3:aa:5d:21:91:ef:da:10:
//        bf:92:35:d3:7b:3a:2a:34:0d:59:41:9b:94:a4:85:66:f3:fa:
//        c3:cd:8b:53:d5:a4:e9:82:70:ea:d2:97:b0:72:10:f9:ce:4a:
//        21:38:b1:88:11:14:3b:93:fa:4e:7a:87:dd:37:e1:38:5f:2c:
//        29:08
const CACertMultiplePEM string = `
-----BEGIN CERTIFICATE-----
MIIC0DCCAjmgAwIBAgIBADANBgkqhkiG9w0BAQUFADBVMQswCQYDVQQGEwJHQjEk
MCIGA1UEChMbQ2VydGlmaWNhdGUgVHJhbnNwYXJlbmN5IENBMQ4wDAYDVQQIEwVX
YWxlczEQMA4GA1UEBxMHRXJ3IFdlbjAeFw0xMjA2MDEwMDAwMDBaFw0yMjA2MDEw
MDAwMDBaMFUxCzAJBgNVBAYTAkdCMSQwIgYDVQQKExtDZXJ0aWZpY2F0ZSBUcmFu
c3BhcmVuY3kgQ0ExDjAMBgNVBAgTBVdhbGVzMRAwDgYDVQQHEwdFcncgV2VuMIGf
MA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDVimhTYhCicRmTbneDIRgcKkATxtB7
jHbrkVfT0PtLO1FuzsvRyY2RxS90P6tjXVUJnNE6uvMa5UFEJFGnTHgW8iQ8+EjP
KDHM5nugSlojgZ88ujfmJNnDvbKZuDnd/iYx0ss6hPx7srXFL8/BT/9Ab1zURmnL
svfP34b7arnRsQIDAQABo4GvMIGsMB0GA1UdDgQWBBRfnYgNyHPmVNT4DdjmsMEk
tEfDVTB9BgNVHSMEdjB0gBRfnYgNyHPmVNT4DdjmsMEktEfDVaFZpFcwVTELMAkG
A1UEBhMCR0IxJDAiBgNVBAoTG0NlcnRpZmljYXRlIFRyYW5zcGFyZW5jeSBDQTEO
MAwGA1UECBMFV2FsZXMxEDAOBgNVBAcTB0VydyBXZW6CAQAwDAYDVR0TBAUwAwEB
/zANBgkqhkiG9w0BAQUFAAOBgQAGCMxKbWTyIF4UbASydvkrDvqUpdryOvw4BmBt
OZDQoeojPUApV2lGOwRmYef6HReZFSCa6i4Kd1F2QRIn18ADB8dHDmFYT9czQiRy
f1HWkLxHqd81TbD26yWVXeGJPE3VICskovPkQNJ0tU4b03YmnKliibduyqQQkOFP
OwqULg==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIC3TCCAkagAwIBAgIBCTANBgkqhkiG9w0BAQUFADBVMQswCQYDVQQGEwJHQjEk
MCIGA1UEChMbQ2VydGlmaWNhdGUgVHJhbnNwYXJlbmN5IENBMQ4wDAYDVQQIEwVX
YWxlczEQMA4GA1UEBxMHRXJ3IFdlbjAeFw0xMjA2MDEwMDAwMDBaFw0yMjA2MDEw
MDAwMDBaMGIxCzAJBgNVBAYTAkdCMTEwLwYDVQQKEyhDZXJ0aWZpY2F0ZSBUcmFu
c3BhcmVuY3kgSW50ZXJtZWRpYXRlIENBMQ4wDAYDVQQIEwVXYWxlczEQMA4GA1UE
BxMHRXJ3IFdlbjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA12pnjRFvUi5V
/4IckGQlCLcHSxTXcRWQZPeSfv3tuHE1oTZe594Yy9XOhl+GDHj0M7TQ09NAdwLn
o+9UKx3+m7qnzflNxZdfxyn4bxBfOBskNTXPnIAPXKeAwdPIRADuZdFu6c9S24rf
/lD1xJM1CyGQv1DVvDbzysWo2q6SzYsCAwEAAaOBrzCBrDAdBgNVHQ4EFgQUllUI
BQJ4R56Hc3ZBMbwUOkfiKaswfQYDVR0jBHYwdIAUX52IDchz5lTU+A3Y5rDBJLRH
w1WhWaRXMFUxCzAJBgNVBAYTAkdCMSQwIgYDVQQKExtDZXJ0aWZpY2F0ZSBUcmFu
c3BhcmVuY3kgQ0ExDjAMBgNVBAgTBVdhbGVzMRAwDgYDVQQHEwdFcncgV2VuggEA
MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADgYEAIgbascZrcdzglcP2qi73
LPd2G+er1/w5wxpM/hvZbWc0yoLyLd5aDIu73YJde28+dhKtjbMAp+IRaYhgIyYi
hMOqXSGR79oQv5I103s6KjQNWUGblKSFZvP6w82LU9Wk6YJw6tKXsHIQ+c5KITix
iBEUO5P6TnqH3TfhOF8sKQg=
-----END CERTIFICATE-----`

// PrecertPEMValid is a test certificate containing a valid CT precertificate extension
//   Data:
//       Version: 3 (0x2)
//       Serial Number: 7 (0x7)
//   Signature Algorithm: sha1WithRSAEncryption
//       Issuer: C=GB, O=Certificate Transparency CA, ST=Wales, L=Erw Wen
//       Validity
//           Not Before: Jun  1 00:00:00 2012 GMT
//           Not After : Jun  1 00:00:00 2022 GMT
//       Subject: C=GB, O=Certificate Transparency, ST=Wales, L=Erw Wen
//       Subject Public Key Info:
//           Public Key Algorithm: rsaEncryption
//               Public-Key: (1024 bit)
//               Modulus:
//                   00:be:ef:98:e7:c2:68:77:ae:38:5f:75:32:5a:0c:
//                   1d:32:9b:ed:f1:8f:aa:f4:d7:96:bf:04:7e:b7:e1:
//                   ce:15:c9:5b:a2:f8:0e:e4:58:bd:7d:b8:6f:8a:4b:
//                   25:21:91:a7:9b:d7:00:c3:8e:9c:03:89:b4:5c:d4:
//                   dc:9a:12:0a:b2:1e:0c:b4:1c:d0:e7:28:05:a4:10:
//                   cd:9c:5b:db:5d:49:27:72:6d:af:17:10:f6:01:87:
//                   37:7e:a2:5b:1a:1e:39:ee:d0:b8:81:19:dc:15:4d:
//                   c6:8f:7d:a8:e3:0c:af:15:8a:33:e6:c9:50:9f:4a:
//                   05:b0:14:09:ff:5d:d8:7e:b5
//               Exponent: 65537 (0x10001)
//       X509v3 extensions:
//           X509v3 Subject Key Identifier:
//               20:31:54:1A:F2:5C:05:FF:D8:65:8B:68:43:79:4F:5E:90:36:F7:B4
//           X509v3 Authority Key Identifier:
//               keyid:5F:9D:88:0D:C8:73:E6:54:D4:F8:0D:D8:E6:B0:C1:24:B4:47:C3:55
//               DirName:/C=GB/O=Certificate Transparency CA/ST=Wales/L=Erw Wen
//               serial:00
//
//           X509v3 Basic Constraints:
//               CA:FALSE
//           CT Precertificate Poison: critical
//               ..
//   Signature Algorithm: sha1WithRSAEncryption
//        02:a1:c3:9e:01:5a:f5:4d:ff:02:3c:33:60:87:5f:ff:34:37:
//        55:2f:1f:09:01:bd:c2:54:31:5f:33:72:b7:23:fb:15:fb:ce:
//        cc:4d:f4:71:a0:ce:4d:8c:54:65:5d:84:87:97:fb:28:1e:3d:
//        fa:bb:46:2d:2c:68:4b:05:6f:ea:7b:63:b4:70:ff:16:6e:32:
//        d4:46:06:35:b3:d2:bc:6d:a8:24:9b:26:30:e7:1f:c3:4f:08:
//        f2:3d:d4:ee:22:8f:8f:74:f6:3d:78:63:11:dd:0a:58:11:40:
//        5f:90:6c:ca:2c:2d:3e:eb:fc:81:99:64:eb:d8:cf:7c:08:86:
//        3f:be
const PrecertPEMValid string = `
-----BEGIN CERTIFICATE-----
MIIC3zCCAkigAwIBAgIBBzANBgkqhkiG9w0BAQUFADBVMQswCQYDVQQGEwJHQjEk
MCIGA1UEChMbQ2VydGlmaWNhdGUgVHJhbnNwYXJlbmN5IENBMQ4wDAYDVQQIEwVX
YWxlczEQMA4GA1UEBxMHRXJ3IFdlbjAeFw0xMjA2MDEwMDAwMDBaFw0yMjA2MDEw
MDAwMDBaMFIxCzAJBgNVBAYTAkdCMSEwHwYDVQQKExhDZXJ0aWZpY2F0ZSBUcmFu
c3BhcmVuY3kxDjAMBgNVBAgTBVdhbGVzMRAwDgYDVQQHEwdFcncgV2VuMIGfMA0G
CSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+75jnwmh3rjhfdTJaDB0ym+3xj6r015a/
BH634c4VyVui+A7kWL19uG+KSyUhkaeb1wDDjpwDibRc1NyaEgqyHgy0HNDnKAWk
EM2cW9tdSSdyba8XEPYBhzd+olsaHjnu0LiBGdwVTcaPfajjDK8VijPmyVCfSgWw
FAn/Xdh+tQIDAQABo4HBMIG+MB0GA1UdDgQWBBQgMVQa8lwF/9hli2hDeU9ekDb3
tDB9BgNVHSMEdjB0gBRfnYgNyHPmVNT4DdjmsMEktEfDVaFZpFcwVTELMAkGA1UE
BhMCR0IxJDAiBgNVBAoTG0NlcnRpZmljYXRlIFRyYW5zcGFyZW5jeSBDQTEOMAwG
A1UECBMFV2FsZXMxEDAOBgNVBAcTB0VydyBXZW6CAQAwCQYDVR0TBAIwADATBgor
BgEEAdZ5AgQDAQH/BAIFADANBgkqhkiG9w0BAQUFAAOBgQACocOeAVr1Tf8CPDNg
h1//NDdVLx8JAb3CVDFfM3K3I/sV+87MTfRxoM5NjFRlXYSHl/soHj36u0YtLGhL
BW/qe2O0cP8WbjLURgY1s9K8bagkmyYw5x/DTwjyPdTuIo+PdPY9eGMR3QpYEUBf
kGzKLC0+6/yBmWTr2M98CIY/vg==
-----END CERTIFICATE-----`

// TestCertPEM is a certificate issued by CACertPEM, no CT extensions
//   Data:
//       Version: 3 (0x2)
//       Serial Number: 6 (0x6)
//   Signature Algorithm: sha1WithRSAEncryption
//       Issuer: C=GB, O=Certificate Transparency CA, ST=Wales, L=Erw Wen
//       Validity
//           Not Before: Jun  1 00:00:00 2012 GMT
//           Not After : Jun  1 00:00:00 2022 GMT
//       Subject: C=GB, O=Certificate Transparency, ST=Wales, L=Erw Wen
//       Subject Public Key Info:
//           Public Key Algorithm: rsaEncryption
//               Public-Key: (1024 bit)
//               Modulus:
//                   00:b1:fa:37:93:61:11:f8:79:2d:a2:08:1c:3f:e4:
//                   19:25:00:85:31:dc:7f:2c:65:7b:d9:e1:de:47:04:
//                   16:0b:4c:9f:19:d5:4a:da:44:70:40:4c:1c:51:34:
//                   1b:8f:1f:75:38:dd:dd:28:d9:ac:a4:83:69:fc:56:
//                   46:dd:cc:76:17:f8:16:8a:ae:5b:41:d4:33:31:fc:
//                   a2:da:df:c8:04:d5:72:08:94:90:61:f9:ee:f9:02:
//                   ca:47:ce:88:c6:44:e0:00:f0:6e:ee:cc:ab:dc:9d:
//                   d2:f6:8a:22:cc:b0:9d:c7:6e:0d:bc:73:52:77:65:
//                   b1:a3:7a:8c:67:62:53:dc:c1
//               Exponent: 65537 (0x10001)
//       X509v3 extensions:
//           X509v3 Subject Key Identifier:
//               6A:0D:98:2A:3B:62:C4:4B:6D:2E:F4:E9:BB:7A:01:AA:9C:B7:98:E2
//           X509v3 Authority Key Identifier:
//               keyid:5F:9D:88:0D:C8:73:E6:54:D4:F8:0D:D8:E6:B0:C1:24:B4:47:C3:55
//               DirName:/C=GB/O=Certificate Transparency CA/ST=Wales/L=Erw Wen
//               serial:00
//
//           X509v3 Basic Constraints:
//               CA:FALSE
//   Signature Algorithm: sha1WithRSAEncryption
//        17:1c:d8:4a:ac:41:4a:9a:03:0f:22:aa:c8:f6:88:b0:81:b2:
//        70:9b:84:8b:4e:55:11:40:6c:d7:07:fe:d0:28:59:7a:9f:ae:
//        fc:2e:ee:29:78:d6:33:aa:ac:14:ed:32:35:19:7d:a8:7e:0f:
//        71:b8:87:5f:1a:c9:e7:8b:28:17:49:dd:ed:d0:07:e3:ec:f5:
//        06:45:f8:cb:f6:67:25:6c:d6:a1:64:7b:5e:13:20:3b:b8:58:
//        2d:e7:d6:69:6f:65:6d:1c:60:b9:5f:45:6b:7f:cf:33:85:71:
//        90:8f:1c:69:72:7d:24:c4:fc:cd:24:92:95:79:58:14:d1:da:
//        c0:e6
const TestCertPEM string = `
-----BEGIN CERTIFICATE-----
MIICyjCCAjOgAwIBAgIBBjANBgkqhkiG9w0BAQUFADBVMQswCQYDVQQGEwJHQjEk
MCIGA1UEChMbQ2VydGlmaWNhdGUgVHJhbnNwYXJlbmN5IENBMQ4wDAYDVQQIEwVX
YWxlczEQMA4GA1UEBxMHRXJ3IFdlbjAeFw0xMjA2MDEwMDAwMDBaFw0yMjA2MDEw
MDAwMDBaMFIxCzAJBgNVBAYTAkdCMSEwHwYDVQQKExhDZXJ0aWZpY2F0ZSBUcmFu
c3BhcmVuY3kxDjAMBgNVBAgTBVdhbGVzMRAwDgYDVQQHEwdFcncgV2VuMIGfMA0G
CSqGSIb3DQEBAQUAA4GNADCBiQKBgQCx+jeTYRH4eS2iCBw/5BklAIUx3H8sZXvZ
4d5HBBYLTJ8Z1UraRHBATBxRNBuPH3U43d0o2aykg2n8VkbdzHYX+BaKrltB1DMx
/KLa38gE1XIIlJBh+e75AspHzojGROAA8G7uzKvcndL2iiLMsJ3Hbg28c1J3ZbGj
eoxnYlPcwQIDAQABo4GsMIGpMB0GA1UdDgQWBBRqDZgqO2LES20u9Om7egGqnLeY
4jB9BgNVHSMEdjB0gBRfnYgNyHPmVNT4DdjmsMEktEfDVaFZpFcwVTELMAkGA1UE
BhMCR0IxJDAiBgNVBAoTG0NlcnRpZmljYXRlIFRyYW5zcGFyZW5jeSBDQTEOMAwG
A1UECBMFV2FsZXMxEDAOBgNVBAcTB0VydyBXZW6CAQAwCQYDVR0TBAIwADANBgkq
hkiG9w0BAQUFAAOBgQAXHNhKrEFKmgMPIqrI9oiwgbJwm4SLTlURQGzXB/7QKFl6
n678Lu4peNYzqqwU7TI1GX2ofg9xuIdfGsnniygXSd3t0Afj7PUGRfjL9mclbNah
ZHteEyA7uFgt59Zpb2VtHGC5X0Vrf88zhXGQjxxpcn0kxPzNJJKVeVgU0drA5g==
-----END CERTIFICATE-----`

// FakeCACertPEM is a test CA cert for testing.
//   Data:
//       Version: 3 (0x2)
//       Serial Number:
//           b6:31:d2:ac:21:ab:65:20
//   Signature Algorithm: sha256WithRSAEncryption
//       Issuer: C=GB, ST=London, L=London, O=Google, OU=Eng, CN=FakeCertificateAuthority
//       Validity
//           Not Before: Jul 11 12:23:26 2016 GMT
//           Not After : Jul 11 12:23:26 2017 GMT
//       Subject: C=GB, ST=London, L=London, O=Google, OU=Eng, CN=FakeCertificateAuthority
//       Subject Public Key Info:
//           Public Key Algorithm: rsaEncryption
//               Public-Key: (2048 bit)
//               Modulus:
//                   00:a5:41:9a:7a:2d:98:a3:b5:78:6f:15:21:db:0c:
//                   c1:0e:a1:f8:26:f5:b3:b2:67:85:dc:a1:e6:b7:83:
//                   6d:da:63:da:d0:f6:a3:ff:bc:43:f5:2b:9f:00:19:
//                   6e:6b:60:4b:43:20:6e:e2:cb:2e:b6:65:ed:9b:dc:
//                   80:c3:e1:5a:96:af:60:78:0e:0e:fb:8f:ea:3e:3d:
//                   c9:67:8f:a4:57:1c:ba:e4:f3:37:a9:2f:dd:11:9d:
//                   10:5d:e5:d6:ef:d4:3b:06:d9:34:43:42:bb:bb:be:
//                   43:40:2b:e3:b6:d1:b5:6c:58:12:34:96:14:d4:fc:
//                   49:79:c5:26:8c:24:7d:b3:12:f5:f6:3e:b7:41:46:
//                   6b:6d:3a:41:fd:7c:e3:b5:fc:96:6c:c6:cc:ad:8d:
//                   48:09:73:44:64:ea:4f:17:1d:0a:4b:14:5a:19:07:
//                   4a:32:0f:41:2e:e4:85:bd:a1:e1:9b:de:63:7c:3b:
//                   bc:ec:aa:93:2a:0b:a8:c7:24:34:54:42:38:a5:d1:
//                   0c:c4:f9:9e:7c:69:42:71:77:d7:95:aa:bb:13:3d:
//                   f3:cc:c7:5d:b3:fd:76:25:25:e3:da:14:0e:59:81:
//                   e8:2c:58:e8:09:29:7d:22:02:91:95:81:eb:55:6f:
//                   2f:17:b9:af:4a:f3:84:8b:24:6e:ea:14:6b:bb:90:
//                   84:35
//               Exponent: 65537 (0x10001)
//       X509v3 extensions:
//           X509v3 Subject Key Identifier:
//               01:02:03:04
//           X509v3 Authority Key Identifier:
//               keyid:01:02:03:04
//
//           X509v3 Basic Constraints: critical
//               CA:TRUE, pathlen:10
//           X509v3 Key Usage: critical
//               Digital Signature, Non Repudiation, Key Encipherment, Data Encipherment, Key Agreement, Certificate Sign, CRL Sign, Encipher Only, Decipher Only
//   Signature Algorithm: sha256WithRSAEncryption
//        92:be:33:eb:d5:d4:32:e7:9e:4e:65:2a:e8:3f:67:b8:f4:d7:
//        34:ab:95:11:6a:5d:ba:fd:57:9b:94:6e:8d:20:be:fb:7a:e1:
//        49:ca:39:ea:92:d3:81:5a:b1:87:a3:9f:50:a4:e0:1e:11:de:
//        c4:d1:07:a1:ca:d1:97:1a:92:bd:73:9a:11:ec:6a:9a:52:11:
//        2d:40:e1:3b:4f:3c:1f:81:3f:4c:ab:6a:02:84:4f:8b:18:36:
//        7a:cc:5c:a9:0e:25:2b:cd:57:53:88:d9:eb:82:b1:ce:62:76:
//        56:d4:23:9e:01:b3:6d:2b:49:ea:d4:3a:c2:f5:76:a7:b3:2d:
//        24:97:6f:b4:1c:74:6b:95:85:f6:b5:41:56:82:3c:ed:be:96:
//        1e:5e:6a:2d:7b:f7:fd:7d:6e:3f:fb:c2:ec:61:b3:7c:7f:3b:
//        f5:9c:64:61:5f:02:93:87:cd:81:f9:7e:53:3e:c1:f5:79:85:
//        f4:41:87:c7:ca:bd:af:ab:2b:a4:aa:a8:1d:2c:50:ad:23:8f:
//        db:13:1d:71:8a:85:bd:ac:59:6c:c4:53:c5:71:0c:90:91:f3:
//        0b:41:ef:da:6e:27:bb:09:57:9c:97:b9:d7:fc:20:96:c5:75:
//        96:ce:2e:6c:a8:b6:6e:b0:4d:0f:3e:01:95:ea:8b:cd:ae:47:
//        d0:d9:01:b7
const FakeCACertPEM string = `
-----BEGIN CERTIFICATE-----
MIIDrDCCApSgAwIBAgIJALYx0qwhq2UgMA0GCSqGSIb3DQEBCwUAMHExCzAJBgNV
BAYTAkdCMQ8wDQYDVQQIDAZMb25kb24xDzANBgNVBAcMBkxvbmRvbjEPMA0GA1UE
CgwGR29vZ2xlMQwwCgYDVQQLDANFbmcxITAfBgNVBAMMGEZha2VDZXJ0aWZpY2F0
ZUF1dGhvcml0eTAeFw0xNjA3MTExMjIzMjZaFw0xNzA3MTExMjIzMjZaMHExCzAJ
BgNVBAYTAkdCMQ8wDQYDVQQIDAZMb25kb24xDzANBgNVBAcMBkxvbmRvbjEPMA0G
A1UECgwGR29vZ2xlMQwwCgYDVQQLDANFbmcxITAfBgNVBAMMGEZha2VDZXJ0aWZp
Y2F0ZUF1dGhvcml0eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKVB
mnotmKO1eG8VIdsMwQ6h+Cb1s7Jnhdyh5reDbdpj2tD2o/+8Q/UrnwAZbmtgS0Mg
buLLLrZl7ZvcgMPhWpavYHgODvuP6j49yWePpFccuuTzN6kv3RGdEF3l1u/UOwbZ
NENCu7u+Q0Ar47bRtWxYEjSWFNT8SXnFJowkfbMS9fY+t0FGa206Qf1847X8lmzG
zK2NSAlzRGTqTxcdCksUWhkHSjIPQS7khb2h4ZveY3w7vOyqkyoLqMckNFRCOKXR
DMT5nnxpQnF315WquxM988zHXbP9diUl49oUDlmB6CxY6AkpfSICkZWB61VvLxe5
r0rzhIskbuoUa7uQhDUCAwEAAaNHMEUwDQYDVR0OBAYEBAECAwQwDwYDVR0jBAgw
BoAEAQIDBDASBgNVHRMBAf8ECDAGAQH/AgEKMA8GA1UdDwEB/wQFAwMH/4AwDQYJ
KoZIhvcNAQELBQADggEBAJK+M+vV1DLnnk5lKug/Z7j01zSrlRFqXbr9V5uUbo0g
vvt64UnKOeqS04FasYejn1Ck4B4R3sTRB6HK0Zcakr1zmhHsappSES1A4TtPPB+B
P0yragKET4sYNnrMXKkOJSvNV1OI2euCsc5idlbUI54Bs20rSerUOsL1dqezLSSX
b7QcdGuVhfa1QVaCPO2+lh5eai179/19bj/7wuxhs3x/O/WcZGFfApOHzYH5flM+
wfV5hfRBh8fKva+rK6SqqB0sUK0jj9sTHXGKhb2sWWzEU8VxDJCR8wtB79puJ7sJ
V5yXudf8IJbFdZbOLmyotm6wTQ8+AZXqi82uR9DZAbc=
-----END CERTIFICATE-----`

// FakeIntermediateCertPEM is a test intermediate CA cert.
//   Data:
//       Version: 3 (0x2)
//       Serial Number: 4792439526061490155 (0x42822a5b866fbfeb)
//   Signature Algorithm: sha256WithRSAEncryption
//       Issuer: C=GB, ST=London, L=London, O=Google, OU=Eng, CN=FakeCertificateAuthority
//       Validity
//           Not Before: May 13 14:26:44 2016 GMT
//           Not After : Jul 12 14:26:44 2019 GMT
//       Subject: C=GB, ST=London, L=London, O=Google, OU=Eng, CN=FakeIntermediateAuthority
//       Subject Public Key Info:
//           Public Key Algorithm: rsaEncryption
//               Public-Key: (2048 bit)
//               Modulus:
//                   00:ca:a4:0c:7a:6d:e9:26:22:d4:67:19:c8:29:40:
//                   c6:bd:cb:44:39:e7:fa:84:01:1d:b3:04:15:48:37:
//                   fa:55:d5:98:4b:2a:ff:14:0e:d6:ce:27:6b:29:d5:
//                   e8:8d:39:eb:be:97:be:53:21:d2:a3:f2:27:ef:46:
//                   68:1c:6f:84:77:85:b4:68:78:7a:d4:3d:50:49:89:
//                   8f:9e:6b:4a:ce:74:c0:0f:c8:68:38:7e:ae:82:ae:
//                   91:0c:6d:87:24:c4:48:f3:e0:8e:a8:3e:0c:f8:e1:
//                   e8:7f:a1:dd:29:f4:d0:eb:3a:b2:38:77:0f:1a:4e:
//                   a6:14:c4:b1:db:5b:ed:f9:a4:f0:9d:1e:d8:a8:d0:
//                   40:28:d6:fc:69:44:0b:37:37:e7:d6:fd:29:b0:70:
//                   36:47:00:89:81:5a:c9:51:cf:2d:a0:80:76:fc:d8:
//                   57:28:87:81:71:e4:10:4b:39:16:51:f2:85:ed:a0:
//                   34:41:bf:f3:52:28:f1:cd:c4:dc:31:f9:26:14:fd:
//                   b6:65:51:2f:76:e9:82:94:fc:2a:be:1a:a0:58:54:
//                   d8:b5:de:e3:96:08:07:50:3d:0e:35:26:e5:3a:c7:
//                   67:e8:8d:b6:f1:34:61:f6:0c:47:d2:fd:0b:51:cf:
//                   a6:99:97:d4:26:a1:12:14:dd:a2:0e:e5:68:4d:75:
//                   f7:c5
//               Exponent: 65537 (0x10001)
//       X509v3 extensions:
//           X509v3 Authority Key Identifier:
//               keyid:01:02:03:04
//
//           X509v3 Basic Constraints: critical
//               CA:TRUE, pathlen:0
//           X509v3 Key Usage: critical
//               Digital Signature, Non Repudiation, Key Encipherment, Data Encipherment, Key Agreement, Certificate Sign, CRL Sign, Encipher Only, Decipher Only
//   Signature Algorithm: sha256WithRSAEncryption
//        01:e2:3a:0c:00:bc:4c:e1:ac:d3:10:54:0c:fc:6b:e4:ac:c8:
//        c2:00:05:74:39:3f:c5:9b:25:e1:e3:90:88:a9:13:8f:b9:66:
//        99:2b:65:55:ea:f6:9f:30:39:d9:18:9c:e1:f1:e1:63:62:f4:
//        f5:46:41:b2:c6:f4:8b:9f:87:d7:e9:93:c7:32:c9:15:83:8b:
//        e5:76:d3:f0:8d:36:d6:b0:32:ad:c2:95:5d:dd:58:2f:7c:4e:
//        3e:16:5f:f0:57:0c:27:98:da:32:b8:8d:81:95:f9:db:38:dc:
//        76:15:d1:3a:01:9a:fb:eb:71:ca:bf:53:bc:d8:30:61:5c:42:
//        22:81:0a:5c:f9:6d:31:3e:18:cb:eb:65:67:0e:e4:0f:cb:87:
//        7f:22:d9:84:85:d6:2f:12:7c:35:67:00:e0:65:02:06:66:96:
//        57:21:78:7a:46:b1:67:d2:9d:db:88:96:55:2f:4e:c4:6f:10:
//        8b:1a:6a:a7:d5:2e:5e:50:a5:15:c1:3a:af:2d:6e:32:bc:e7:
//        fd:a0:e9:e6:ab:d6:8c:4f:84:9d:70:f6:17:6c:f9:64:c5:5e:
//        49:87:91:6b:ca:25:e6:d8:d7:7b:77:39:f4:a3:03:28:5a:45:
//        2b:7c:85:dc:c3:cc:74:c5:c2:33:e3:1d:3f:21:e9:d5:3b:fe:
//        13:1d:91:48
const FakeIntermediateCertPEM string = `
-----BEGIN CERTIFICATE-----
MIIDnTCCAoWgAwIBAgIIQoIqW4Zvv+swDQYJKoZIhvcNAQELBQAwcTELMAkGA1UE
BhMCR0IxDzANBgNVBAgMBkxvbmRvbjEPMA0GA1UEBwwGTG9uZG9uMQ8wDQYDVQQK
DAZHb29nbGUxDDAKBgNVBAsMA0VuZzEhMB8GA1UEAwwYRmFrZUNlcnRpZmljYXRl
QXV0aG9yaXR5MB4XDTE2MDUxMzE0MjY0NFoXDTE5MDcxMjE0MjY0NFowcjELMAkG
A1UEBhMCR0IxDzANBgNVBAgMBkxvbmRvbjEPMA0GA1UEBwwGTG9uZG9uMQ8wDQYD
VQQKDAZHb29nbGUxDDAKBgNVBAsMA0VuZzEiMCAGA1UEAwwZRmFrZUludGVybWVk
aWF0ZUF1dGhvcml0eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMqk
DHpt6SYi1GcZyClAxr3LRDnn+oQBHbMEFUg3+lXVmEsq/xQO1s4naynV6I05676X
vlMh0qPyJ+9GaBxvhHeFtGh4etQ9UEmJj55rSs50wA/IaDh+roKukQxthyTESPPg
jqg+DPjh6H+h3Sn00Os6sjh3DxpOphTEsdtb7fmk8J0e2KjQQCjW/GlECzc359b9
KbBwNkcAiYFayVHPLaCAdvzYVyiHgXHkEEs5FlHyhe2gNEG/81Io8c3E3DH5JhT9
tmVRL3bpgpT8Kr4aoFhU2LXe45YIB1A9DjUm5TrHZ+iNtvE0YfYMR9L9C1HPppmX
1CahEhTdog7laE1198UCAwEAAaM4MDYwDwYDVR0jBAgwBoAEAQIDBDASBgNVHRMB
Af8ECDAGAQH/AgEAMA8GA1UdDwEB/wQFAwMH/4AwDQYJKoZIhvcNAQELBQADggEB
AAHiOgwAvEzhrNMQVAz8a+SsyMIABXQ5P8WbJeHjkIipE4+5ZpkrZVXq9p8wOdkY
nOHx4WNi9PVGQbLG9Iufh9fpk8cyyRWDi+V20/CNNtawMq3ClV3dWC98Tj4WX/BX
DCeY2jK4jYGV+ds43HYV0ToBmvvrccq/U7zYMGFcQiKBClz5bTE+GMvrZWcO5A/L
h38i2YSF1i8SfDVnAOBlAgZmllcheHpGsWfSnduIllUvTsRvEIsaaqfVLl5QpRXB
Oq8tbjK85/2g6ear1oxPhJ1w9hds+WTFXkmHkWvKJebY13t3OfSjAyhaRSt8hdzD
zHTFwjPjHT8h6dU7/hMdkUg=
-----END CERTIFICATE-----`

// LeafSignedByFakeIntermediateCertPEM is a test cert signed by the intermediate CA.
//   Data:
//       Version: 3 (0x2)
//       Serial Number: 4792439526061490155 (0x42822a5b866fbfeb)
//   Signature Algorithm: sha256WithRSAEncryption
//       Issuer: C=GB, ST=London, L=London, O=Google, OU=Eng, CN=FakeIntermediateAuthority
//       Validity
//           Not Before: May 13 14:26:44 2016 GMT
//           Not After : Jul 12 14:26:44 2019 GMT
//       Subject: C=US, ST=California, L=Mountain View, O=Google Inc, CN=*.google.com, SN=RFC5280 s4.2.1.9 'The pathLenConstraint field ... gives the maximum number of non-self-issued intermediate certificates that may follow this certificate in a valid certification path.', GN=Intermediate CA cert used to sign
//       Subject Public Key Info:
//           Public Key Algorithm: id-ecPublicKey
//               Public-Key: (256 bit)
//                   04:c4:09:39:84:f5:15:8d:12:54:b2:02:9c:f9:01:
//                   e2:6d:35:47:d4:0d:d0:11:61:66:09:35:1d:cb:12:
//                   14:95:b2:3f:ff:35:bd:22:8e:4d:fc:38:50:2d:22:
//                   d6:98:1e:ca:a0:23:af:a4:96:7e:32:d1:82:5f:31:
//                   57:fb:28:ff:37
//               ASN1 OID: prime256v1
//               NIST CURVE: P-256
//       X509v3 extensions:
//           X509v3 Extended Key Usage:
//               TLS Web Server Authentication, TLS Web Client Authentication
//           X509v3 Subject Alternative Name:
//               DNS:*.google.com, DNS:*.android.com, DNS:*.appengine.google.com, DNS:*.cloud.google.com,
//               DNS:*.google-analytics.com, DNS:*.google.ca, DNS:*.google.cl, DNS:*.google.co.in, DNS:*.google.co.jp,
//               DNS:*.google.co.uk, DNS:*.google.com.ar, DNS:*.google.com.au, DNS:*.google.com.br, DNS:*.google.com.co,
//               DNS:*.google.com.mx, DNS:*.google.com.tr, DNS:*.google.com.vn, DNS:*.google.de, DNS:*.google.es,
//               DNS:*.google.fr, DNS:*.google.hu, DNS:*.google.it, DNS:*.google.nl, DNS:*.google.pl, DNS:*.google.pt,
//               DNS:*.googleadapis.com, DNS:*.googleapis.cn, DNS:*.googlecommerce.com, DNS:*.googlevideo.com,
//               DNS:*.gstatic.cn, DNS:*.gstatic.com, DNS:*.gvt1.com, DNS:*.gvt2.com, DNS:*.metric.gstatic.com,
//               DNS:*.urchin.com, DNS:*.url.google.com, DNS:*.youtube-nocookie.com, DNS:*.youtube.com,
//               DNS:*.youtubeeducation.com, DNS:*.ytimg.com, DNS:android.clients.google.com, DNS:android.com, DNS:g.co,
//               DNS:goo.gl, DNS:google-analytics.com, DNS:google.com, DNS:googlecommerce.com, DNS:urchin.com,
//               DNS:youtu.be, DNS:youtube.com, DNS:youtubeeducation.com
//           X509v3 Key Usage:
//               Digital Signature
//           Authority Information Access:
//               CA Issuers - URI:http://pki.google.com/GIAG2.crt
//               OCSP - URI:http://clients1.google.com/ocsp
//
//           X509v3 Subject Key Identifier:
//               DB:F4:6E:63:EE:E2:DC:BE:BF:38:60:4F:98:31:D0:64:44:F1:63:D8
//           X509v3 Basic Constraints: critical
//               CA:FALSE
//           X509v3 Certificate Policies:
//               Policy: 1.3.6.1.4.1.11129.2.5.1
//               Policy: 2.23.140.1.2.2
//
//           X509v3 CRL Distribution Points:
//
//               Full Name:
//                 URI:http://pki.google.com/GIAG2.crl
//
//   Signature Algorithm: sha256WithRSAEncryption
//        0e:a6:6f:79:7d:38:4b:60:f0:c1:76:9c:4e:92:f5:24:ce:12:
//        34:72:94:95:8d:cf:1c:0c:d6:78:6b:ee:66:2b:50:36:22:7a:
//        be:ff:22:c7:dd:93:2c:40:83:2f:a0:37:29:8f:bb:98:22:bf:
//        8e:c6:6c:b4:8b:8f:e9:1e:0f:bd:8a:df:df:f5:c9:aa:79:ac:
//        00:e6:ca:a6:1a:74:8e:67:f9:5f:09:82:3c:f9:b4:5b:30:85:
//        0b:ae:28:c2:b8:9c:23:7c:6a:59:66:ca:8e:bd:20:6e:20:e4:
//        b3:46:f8:06:56:99:5c:b3:47:62:b6:e4:f6:92:10:85:ae:46:
//        e5:c1:af:c1:a8:8a:b3:b6:f3:fb:2e:e1:26:56:98:e4:aa:de:
//        29:0b:71:ef:0f:45:d4:c6:ce:4f:21:d6:59:18:89:df:7a:ac:
//        a6:93:97:de:45:e5:87:06:e3:c7:a4:f2:14:39:b2:b1:99:0b:
//        7e:85:cc:3a:62:c1:c4:fb:40:7c:e1:7b:71:f4:13:1e:e2:aa:
//        94:7e:ba:a6:b5:65:e7:f6:e9:c1:c3:1a:92:62:c0:aa:c4:74:
//        29:43:ee:f4:a6:6b:81:c6:50:7d:b3:a2:d2:b4:8c:c4:f6:cc:
//        9a:0e:65:32:8f:14:65:8c:a0:30:20:d5:7a:cf:48:fb:84:a4:
//        3a:30:fa:44
const LeafSignedByFakeIntermediateCertPEM string = `
-----BEGIN CERTIFICATE-----
MIIH6DCCBtCgAwIBAgIIQoIqW4Zvv+swDQYJKoZIhvcNAQELBQAwcjELMAkGA1UE
BhMCR0IxDzANBgNVBAgMBkxvbmRvbjEPMA0GA1UEBwwGTG9uZG9uMQ8wDQYDVQQK
DAZHb29nbGUxDDAKBgNVBAsMA0VuZzEiMCAGA1UEAwwZRmFrZUludGVybWVkaWF0
ZUF1dGhvcml0eTAeFw0xNjA1MTMxNDI2NDRaFw0xOTA3MTIxNDI2NDRaMIIBWDEL
MAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50
YWluIFZpZXcxEzARBgNVBAoMCkdvb2dsZSBJbmMxFTATBgNVBAMMDCouZ29vZ2xl
LmNvbTGBwzCBwAYDVQQEDIG4UkZDNTI4MCBzNC4yLjEuOSAnVGhlIHBhdGhMZW5D
b25zdHJhaW50IGZpZWxkIC4uLiBnaXZlcyB0aGUgbWF4aW11bSBudW1iZXIgb2Yg
bm9uLXNlbGYtaXNzdWVkIGludGVybWVkaWF0ZSBjZXJ0aWZpY2F0ZXMgdGhhdCBt
YXkgZm9sbG93IHRoaXMgY2VydGlmaWNhdGUgaW4gYSB2YWxpZCBjZXJ0aWZpY2F0
aW9uIHBhdGguJzEqMCgGA1UEKgwhSW50ZXJtZWRpYXRlIENBIGNlcnQgdXNlZCB0
byBzaWduMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExAk5hPUVjRJUsgKc+QHi
bTVH1A3QEWFmCTUdyxIUlbI//zW9Io5N/DhQLSLWmB7KoCOvpJZ+MtGCXzFX+yj/
N6OCBGMwggRfMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjCCA0IGA1Ud
EQSCAzkwggM1ggwqLmdvb2dsZS5jb22CDSouYW5kcm9pZC5jb22CFiouYXBwZW5n
aW5lLmdvb2dsZS5jb22CEiouY2xvdWQuZ29vZ2xlLmNvbYIWKi5nb29nbGUtYW5h
bHl0aWNzLmNvbYILKi5nb29nbGUuY2GCCyouZ29vZ2xlLmNsgg4qLmdvb2dsZS5j
by5pboIOKi5nb29nbGUuY28uanCCDiouZ29vZ2xlLmNvLnVrgg8qLmdvb2dsZS5j
b20uYXKCDyouZ29vZ2xlLmNvbS5hdYIPKi5nb29nbGUuY29tLmJygg8qLmdvb2ds
ZS5jb20uY2+CDyouZ29vZ2xlLmNvbS5teIIPKi5nb29nbGUuY29tLnRygg8qLmdv
b2dsZS5jb20udm6CCyouZ29vZ2xlLmRlggsqLmdvb2dsZS5lc4ILKi5nb29nbGUu
ZnKCCyouZ29vZ2xlLmh1ggsqLmdvb2dsZS5pdIILKi5nb29nbGUubmyCCyouZ29v
Z2xlLnBsggsqLmdvb2dsZS5wdIISKi5nb29nbGVhZGFwaXMuY29tgg8qLmdvb2ds
ZWFwaXMuY26CFCouZ29vZ2xlY29tbWVyY2UuY29tghEqLmdvb2dsZXZpZGVvLmNv
bYIMKi5nc3RhdGljLmNugg0qLmdzdGF0aWMuY29tggoqLmd2dDEuY29tggoqLmd2
dDIuY29tghQqLm1ldHJpYy5nc3RhdGljLmNvbYIMKi51cmNoaW4uY29tghAqLnVy
bC5nb29nbGUuY29tghYqLnlvdXR1YmUtbm9jb29raWUuY29tgg0qLnlvdXR1YmUu
Y29tghYqLnlvdXR1YmVlZHVjYXRpb24uY29tggsqLnl0aW1nLmNvbYIaYW5kcm9p
ZC5jbGllbnRzLmdvb2dsZS5jb22CC2FuZHJvaWQuY29tggRnLmNvggZnb28uZ2yC
FGdvb2dsZS1hbmFseXRpY3MuY29tggpnb29nbGUuY29tghJnb29nbGVjb21tZXJj
ZS5jb22CCnVyY2hpbi5jb22CCHlvdXR1LmJlggt5b3V0dWJlLmNvbYIUeW91dHVi
ZWVkdWNhdGlvbi5jb20wDAYDVR0PBAUDAweAADBoBggrBgEFBQcBAQRcMFowKwYI
KwYBBQUHMAKGH2h0dHA6Ly9wa2kuZ29vZ2xlLmNvbS9HSUFHMi5jcnQwKwYIKwYB
BQUHMAGGH2h0dHA6Ly9jbGllbnRzMS5nb29nbGUuY29tL29jc3AwHQYDVR0OBBYE
FNv0bmPu4ty+vzhgT5gx0GRE8WPYMAwGA1UdEwEB/wQCMAAwIQYDVR0gBBowGDAM
BgorBgEEAdZ5AgUBMAgGBmeBDAECAjAwBgNVHR8EKTAnMCWgI6Ahhh9odHRwOi8v
cGtpLmdvb2dsZS5jb20vR0lBRzIuY3JsMA0GCSqGSIb3DQEBCwUAA4IBAQAOpm95
fThLYPDBdpxOkvUkzhI0cpSVjc8cDNZ4a+5mK1A2Inq+/yLH3ZMsQIMvoDcpj7uY
Ir+Oxmy0i4/pHg+9it/f9cmqeawA5sqmGnSOZ/lfCYI8+bRbMIULrijCuJwjfGpZ
ZsqOvSBuIOSzRvgGVplcs0dituT2khCFrkblwa/BqIqztvP7LuEmVpjkqt4pC3Hv
D0XUxs5PIdZZGInfeqymk5feReWHBuPHpPIUObKxmQt+hcw6YsHE+0B84Xtx9BMe
4qqUfrqmtWXn9unBwxqSYsCqxHQpQ+70pmuBxlB9s6LStIzE9syaDmUyjxRljKAw
INV6z0j7hKQ6MPpE
-----END CERTIFICATE-----`

// The next section holds copies and variants of test certs from ../../testdata/

// FakeRootCACertPEM is a root CA taken from ../../testdata/fake-ca.cert.
//  Data:
//      Version: 3 (0x2)
//      Serial Number: 67554046 (0x406cafe)
//  Signature Algorithm: ecdsa-with-SHA256
//      Issuer: C=GB, ST=London, L=London, O=Google, OU=Eng, CN=FakeCertificateAuthority
//      Validity
//          Not Before: Dec  7 15:13:36 2016 GMT
//          Not After : Dec  5 15:13:36 2026 GMT
//      Subject: C=GB, ST=London, L=London, O=Google, OU=Eng, CN=FakeCertificateAuthority
//      Subject Public Key Info:
//          Public Key Algorithm: id-ecPublicKey
//              Public-Key: (256 bit)
//              pub:
//                  04:f2:d3:07:ef:7e:df:cf:ce:f4:f4:0a:5b:bc:9e:
//                  3f:cb:1c:fd:0c:46:dc:85:fb:c1:f6:d3:b2:ba:1d:
//                  51:f1:98:6c:48:a8:15:46:45:63:ca:df:d6:c9:ac:
//                  cf:60:3b:c7:4e:dd:b8:d2:16:ab:a0:09:24:1d:09:
//                  66:1e:4d:eb:a1
//              ASN1 OID: prime256v1
//              NIST CURVE: P-256
//      X509v3 extensions:
//          X509v3 Subject Key Identifier:
//              01:02:03:04
//          X509v3 Authority Key Identifier:
//              keyid:01:02:03:04
//          X509v3 Basic Constraints: critical
//              CA:TRUE, pathlen:10
//          X509v3 Key Usage: critical
//              Digital Signature, Non Repudiation, Key Encipherment, Data Encipherment, Key Agreement, Certificate Sign, CRL Sign, Encipher Only, Decipher Only
//  Signature Algorithm: ecdsa-with-SHA256
//       30:46:02:21:00:a6:28:49:39:43:6f:80:e4:43:a6:1e:3b:aa:
//       89:5e:c2:25:60:2a:e1:39:bd:55:43:ae:4d:5c:a9:a6:ef:ac:
//       65:02:21:00:c9:c5:08:c6:59:93:b4:86:70:a5:6b:54:2b:5b:
//       fc:0c:88:6b:b0:23:07:2b:c7:0c:27:de:87:2d:96:80:d5:56
const FakeRootCACertPEM = `
-----BEGIN CERTIFICATE-----
MIICHDCCAcGgAwIBAgIEBAbK/jAKBggqhkjOPQQDAjBxMQswCQYDVQQGEwJHQjEP
MA0GA1UECBMGTG9uZG9uMQ8wDQYDVQQHEwZMb25kb24xDzANBgNVBAoTBkdvb2ds
ZTEMMAoGA1UECxMDRW5nMSEwHwYDVQQDExhGYWtlQ2VydGlmaWNhdGVBdXRob3Jp
dHkwHhcNMTYxMjA3MTUxMzM2WhcNMjYxMjA1MTUxMzM2WjBxMQswCQYDVQQGEwJH
QjEPMA0GA1UECBMGTG9uZG9uMQ8wDQYDVQQHEwZMb25kb24xDzANBgNVBAoTBkdv
b2dsZTEMMAoGA1UECxMDRW5nMSEwHwYDVQQDExhGYWtlQ2VydGlmaWNhdGVBdXRo
b3JpdHkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATy0wfvft/PzvT0Clu8nj/L
HP0MRtyF+8H207K6HVHxmGxIqBVGRWPK39bJrM9gO8dO3bjSFqugCSQdCWYeTeuh
o0cwRTANBgNVHQ4EBgQEAQIDBDAPBgNVHSMECDAGgAQBAgMEMBIGA1UdEwEB/wQI
MAYBAf8CAQowDwYDVR0PAQH/BAUDAwf/gDAKBggqhkjOPQQDAgNJADBGAiEApihJ
OUNvgORDph47qolewiVgKuE5vVVDrk1cqabvrGUCIQDJxQjGWZO0hnCla1QrW/wM
iGuwIwcrxwwn3octloDVVg==
-----END CERTIFICATE-----`

// FakeIntermediateWithPolicyConstraintsCertPEM is an intermediate CA cert that includes a
// critical PolicyConstraints extension; based on ../../testdata/int-ca.cert.
//  Data:
//      Version: 3 (0x2)
//      Serial Number: 1111638594 (0x42424242)
//  Signature Algorithm: ecdsa-with-SHA256
//      Issuer: C=GB, ST=London, L=London, O=Google, OU=Eng, CN=FakeCertificateAuthority
//      Validity
//          Not Before: Feb 13 09:33:59 2018 GMT
//          Not After : Dec 23 09:33:59 2027 GMT
//      Subject: C=GB, ST=London, L=London, O=Google, OU=Eng, CN=FakeIntermediateAuthority
//      Subject Public Key Info:
//          Public Key Algorithm: id-ecPublicKey
//              Public-Key: (256 bit)
//              pub:
//                  04:f1:bf:2d:e8:8c:66:40:e3:a8:d1:54:e0:42:49:
//                  02:cb:dd:47:08:85:c2:67:41:4c:eb:f7:87:cd:8d:
//                  a3:09:c8:18:cc:2e:30:53:16:32:aa:d5:9c:08:73:
//                  c6:76:fa:fa:3a:38:e9:34:35:9c:51:d1:ee:12:81:
//                  5d:98:5f:5d:5d
//              ASN1 OID: prime256v1
//              NIST CURVE: P-256
//      X509v3 extensions:
//          X509v3 Subject Key Identifier:
//              01:02:03:04
//          X509v3 Authority Key Identifier:
//              keyid:01:02:03:04
//          X509v3 Basic Constraints: critical
//              CA:TRUE, pathlen:10
//          X509v3 Policy Constraints: critical
//              Require Explicit Policy:0
//          X509v3 Key Usage: critical
//              Digital Signature, Non Repudiation, Key Encipherment, Data Encipherment, Key Agreement, Certificate Sign, CRL Sign, Encipher Only, Decipher Only
//  Signature Algorithm: ecdsa-with-SHA256
//       30:44:02:20:4c:aa:27:8f:d9:83:32:76:40:17:a1:a8:00:1d:
//       bc:d1:45:b2:53:c6:47:77:48:f1:c3:89:68:5d:f4:7f:5c:52:
//       02:20:39:68:40:5c:fd:f0:2a:e2:3f:34:45:b3:19:2d:e3:4d:
//       58:cd:76:42:19:09:cf:5c:1c:e5:f1:71:e0:39:62:b9
const FakeIntermediateWithPolicyConstraintsCertPEM string = `
-----BEGIN CERTIFICATE-----
MIICLDCCAdOgAwIBAgIEQkJCQjAKBggqhkjOPQQDAjBxMQswCQYDVQQGEwJHQjEP
MA0GA1UECBMGTG9uZG9uMQ8wDQYDVQQHEwZMb25kb24xDzANBgNVBAoTBkdvb2ds
ZTEMMAoGA1UECxMDRW5nMSEwHwYDVQQDExhGYWtlQ2VydGlmaWNhdGVBdXRob3Jp
dHkwHhcNMTgwMjEzMDkzMzU5WhcNMjcxMjIzMDkzMzU5WjByMQswCQYDVQQGEwJH
QjEPMA0GA1UECBMGTG9uZG9uMQ8wDQYDVQQHEwZMb25kb24xDzANBgNVBAoTBkdv
b2dsZTEMMAoGA1UECxMDRW5nMSIwIAYDVQQDExlGYWtlSW50ZXJtZWRpYXRlQXV0
aG9yaXR5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8b8t6IxmQOOo0VTgQkkC
y91HCIXCZ0FM6/eHzY2jCcgYzC4wUxYyqtWcCHPGdvr6OjjpNDWcUdHuEoFdmF9d
XaNYMFYwDQYDVR0OBAYEBAECAwQwDwYDVR0jBAgwBoAEAQIDBDASBgNVHRMBAf8E
CDAGAQH/AgEKMA8GA1UdJAEB/wQFMAOAAQAwDwYDVR0PAQH/BAUDAwf/gDAKBggq
hkjOPQQDAgNHADBEAiBMqieP2YMydkAXoagAHbzRRbJTxkd3SPHDiWhd9H9cUgIg
OWhAXP3wKuI/NEWzGS3jTVjNdkIZCc9cHOXxceA5Yrk=
-----END CERTIFICATE-----`

// FakeIntermediateWithNameConstraintsCertPEM is an intermediate CA cert that includes a
// critical NameConstraints extension that disallows the leaf below; based on ../../testdata/int-ca.cert.
//  Data:
//      Version: 3 (0x2)
//      Serial Number: 1111638594 (0x42424242)
//  Signature Algorithm: ecdsa-with-SHA256
//      Issuer: C=GB, ST=London, L=London, O=Google, OU=Eng, CN=FakeCertificateAuthority
//      Validity
//          Not Before: Feb 13 11:33:08 2018 GMT
//          Not After : Dec 23 11:33:08 2027 GMT
//      Subject: C=GB, ST=London, L=London, O=Google, OU=Eng, CN=FakeIntermediateAuthority
//      Subject Public Key Info:
//          Public Key Algorithm: id-ecPublicKey
//              Public-Key: (256 bit)
//              pub:
//                  04:f1:bf:2d:e8:8c:66:40:e3:a8:d1:54:e0:42:49:
//                  02:cb:dd:47:08:85:c2:67:41:4c:eb:f7:87:cd:8d:
//                  a3:09:c8:18:cc:2e:30:53:16:32:aa:d5:9c:08:73:
//                  c6:76:fa:fa:3a:38:e9:34:35:9c:51:d1:ee:12:81:
//                  5d:98:5f:5d:5d
//              ASN1 OID: prime256v1
//              NIST CURVE: P-256
//      X509v3 extensions:
//          X509v3 Subject Key Identifier:
//              01:02:03:04
//          X509v3 Authority Key Identifier:
//              keyid:01:02:03:04
//          X509v3 Basic Constraints: critical
//              CA:TRUE, pathlen:10
//          X509v3 Key Usage: critical
//              Digital Signature, Non Repudiation, Key Encipherment, Data Encipherment, Key Agreement, Certificate Sign, CRL Sign, Encipher Only, Decipher Only
//          X509v3 Name Constraints:
//              Permitted:
//                DNS:.csr.pem
//  Signature Algorithm: ecdsa-with-SHA256
//       30:46:02:21:00:fd:11:41:d8:1f:2b:b5:49:8e:27:6e:70:93:
//       2c:f1:c2:e7:b0:a2:40:e2:c6:89:45:fc:99:a5:9b:dc:21:fb:
//       f6:02:21:00:b7:4f:98:bf:1f:dc:92:e7:db:7c:aa:33:7a:40:
//       36:1d:58:19:aa:96:3d:5e:5b:46:5f:47:f6:e3:7d:75:19:4f
const FakeIntermediateWithNameConstraintsCertPEM string = `
-----BEGIN CERTIFICATE-----
MIICNjCCAdugAwIBAgIEQkJCQjAKBggqhkjOPQQDAjBxMQswCQYDVQQGEwJHQjEP
MA0GA1UECBMGTG9uZG9uMQ8wDQYDVQQHEwZMb25kb24xDzANBgNVBAoTBkdvb2ds
ZTEMMAoGA1UECxMDRW5nMSEwHwYDVQQDExhGYWtlQ2VydGlmaWNhdGVBdXRob3Jp
dHkwHhcNMTgwMjEzMTEzMzA4WhcNMjcxMjIzMTEzMzA4WjByMQswCQYDVQQGEwJH
QjEPMA0GA1UECBMGTG9uZG9uMQ8wDQYDVQQHEwZMb25kb24xDzANBgNVBAoTBkdv
b2dsZTEMMAoGA1UECxMDRW5nMSIwIAYDVQQDExlGYWtlSW50ZXJtZWRpYXRlQXV0
aG9yaXR5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8b8t6IxmQOOo0VTgQkkC
y91HCIXCZ0FM6/eHzY2jCcgYzC4wUxYyqtWcCHPGdvr6OjjpNDWcUdHuEoFdmF9d
XaNgMF4wDQYDVR0OBAYEBAECAwQwDwYDVR0jBAgwBoAEAQIDBDASBgNVHRMBAf8E
CDAGAQH/AgEKMA8GA1UdDwEB/wQFAwMH/4AwFwYDVR0eBBAwDqAMMAqCCC5jc3Iu
cGVtMAoGCCqGSM49BAMCA0kAMEYCIQD9EUHYHyu1SY4nbnCTLPHC57CiQOLGiUX8
maWb3CH79gIhALdPmL8f3JLn23yqM3pANh1YGaqWPV5bRl9H9uN9dRlP
-----END CERTIFICATE-----`

// FakeIntermediateWithInvalidNameConstraintsCertPEM is an intermediate CA cert that includes a
// critical NameConstraints extension that disallows the leaf below; based on ../../testdata/int-ca.cert.
//  Data:
//      Version: 3 (0x2)
//      Serial Number: 1111638594 (0x42424242)
//  Signature Algorithm: ecdsa-with-SHA256
//      Issuer: C=GB, ST=London, L=London, O=Google, OU=Eng, CN=FakeCertificateAuthority
//      Validity
//          Not Before: Feb 13 11:42:37 2018 GMT
//          Not After : Dec 23 11:42:37 2027 GMT
//      Subject: C=GB, ST=London, L=London, O=Google, OU=Eng, CN=FakeIntermediateAuthority
//      Subject Public Key Info:
//          Public Key Algorithm: id-ecPublicKey
//              Public-Key: (256 bit)
//              pub:
//                  04:f1:bf:2d:e8:8c:66:40:e3:a8:d1:54:e0:42:49:
//                  02:cb:dd:47:08:85:c2:67:41:4c:eb:f7:87:cd:8d:
//                  a3:09:c8:18:cc:2e:30:53:16:32:aa:d5:9c:08:73:
//                  c6:76:fa:fa:3a:38:e9:34:35:9c:51:d1:ee:12:81:
//                  5d:98:5f:5d:5d
//              ASN1 OID: prime256v1
//              NIST CURVE: P-256
//      X509v3 extensions:
//          X509v3 Subject Key Identifier:
//              01:02:03:04
//          X509v3 Authority Key Identifier:
//              keyid:01:02:03:04
//
//          X509v3 Basic Constraints: critical
//              CA:TRUE, pathlen:10
//          X509v3 Key Usage: critical
//              Digital Signature, Non Repudiation, Key Encipherment, Data Encipherment, Key Agreement, Certificate Sign, CRL Sign, Encipher Only, Decipher Only
//          X509v3 Name Constraints:
//              Permitted:
//                DNS:.xyzzy.pem
//  Signature Algorithm: ecdsa-with-SHA256
//       30:45:02:20:3f:0a:40:60:b6:9e:ea:a5:cd:eb:e4:0e:7c:bc:
//       40:22:b2:e2:14:07:e8:ab:fa:4a:85:2a:41:18:20:f0:31:1a:
//       02:21:00:a4:64:91:6d:79:47:79:0f:16:06:62:a9:88:8b:92:
//       6d:40:fa:54:cb:c9:4f:bc:3f:53:27:e5:cd:12:16:53:7a
const FakeIntermediateWithInvalidNameConstraintsCertPEM string = `
-----BEGIN CERTIFICATE-----
MIICNzCCAd2gAwIBAgIEQkJCQjAKBggqhkjOPQQDAjBxMQswCQYDVQQGEwJHQjEP
MA0GA1UECBMGTG9uZG9uMQ8wDQYDVQQHEwZMb25kb24xDzANBgNVBAoTBkdvb2ds
ZTEMMAoGA1UECxMDRW5nMSEwHwYDVQQDExhGYWtlQ2VydGlmaWNhdGVBdXRob3Jp
dHkwHhcNMTgwMjEzMTE0MjM3WhcNMjcxMjIzMTE0MjM3WjByMQswCQYDVQQGEwJH
QjEPMA0GA1UECBMGTG9uZG9uMQ8wDQYDVQQHEwZMb25kb24xDzANBgNVBAoTBkdv
b2dsZTEMMAoGA1UECxMDRW5nMSIwIAYDVQQDExlGYWtlSW50ZXJtZWRpYXRlQXV0
aG9yaXR5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8b8t6IxmQOOo0VTgQkkC
y91HCIXCZ0FM6/eHzY2jCcgYzC4wUxYyqtWcCHPGdvr6OjjpNDWcUdHuEoFdmF9d
XaNiMGAwDQYDVR0OBAYEBAECAwQwDwYDVR0jBAgwBoAEAQIDBDASBgNVHRMBAf8E
CDAGAQH/AgEKMA8GA1UdDwEB/wQFAwMH/4AwGQYDVR0eBBIwEKAOMAyCCi54eXp6
eS5wZW0wCgYIKoZIzj0EAwIDSAAwRQIgPwpAYLae6qXN6+QOfLxAIrLiFAfoq/pK
hSpBGCDwMRoCIQCkZJFteUd5DxYGYqmIi5JtQPpUy8lPvD9TJ+XNEhZTeg==
-----END CERTIFICATE-----`

// LeafCertPEM is a leaf cert signed by the key in:
//  - FakeIntermediateWithPolicyConstraintsCertPEM
//  - FakeIntermediateWithNameConstraintsCertPEM
//  - FakeIntermediateWithInvalidNameConstraintsCertPEM
// adapted from ../../testdata/leaf01.cert.
//  Data:
//      Version: 3 (0x2)
//      Serial Number: 3735928559 (0xdeadbeef)
//  Signature Algorithm: ecdsa-with-SHA256
//      Issuer: C=GB, ST=London, L=London, O=Google, OU=Eng, CN=FakeIntermediateAuthority
//      Validity
//          Not Before: Feb 13 11:38:39 2018 GMT
//          Not After : Mar 28 11:38:39 2025 GMT
//      Subject: C=GB, ST=London, O=Google, OU=Eng, CN=leaf01.csr.pem
//      Subject Public Key Info:
//          Public Key Algorithm: id-ecPublicKey
//              Public-Key: (256 bit)
//              pub:
//                  04:eb:37:4e:52:45:9c:46:d5:a8:b8:c5:ed:58:b9:
//                  30:29:a6:70:8a:69:a0:26:5c:9e:2f:6e:b8:6b:23:
//                  6c:84:e1:46:3a:98:36:82:44:a5:8a:17:8b:41:82:
//                  32:f4:2d:e0:08:5b:7e:07:38:52:fc:47:56:28:27:
//                  9b:ed:60:8b:ac
//              ASN1 OID: prime256v1
//              NIST CURVE: P-256
//      X509v3 extensions:
//          X509v3 Subject Key Identifier:
//              3F:B2:2F:41:FC:11:9A:D3:8D:A6:85:80:84:86:AE:7E:73:2E:69:5D
//          X509v3 Authority Key Identifier:
//              keyid:01:02:03:04
//          X509v3 Key Usage: critical
//              Digital Signature, Non Repudiation, Key Encipherment, Data Encipherment, Key Agreement, Encipher Only, Decipher Only
//          X509v3 Subject Alternative Name:
//              DNS:leaf01.csr.pem
//  Signature Algorithm: ecdsa-with-SHA256
//       30:46:02:21:00:b5:2a:f3:39:1e:06:b7:77:b2:ad:a8:83:1b:
//       83:38:64:5e:3a:25:51:e9:57:1f:00:53:72:db:08:11:65:3d:
//       f4:02:21:00:a1:4e:5d:b5:9a:8b:10:6e:15:a3:2a:bd:d9:80:
//       91:96:7c:1a:4f:8f:91:dc:44:9f:13:ff:57:f0:5e:ce:32:34
const LeafCertPEM string = `
-----BEGIN CERTIFICATE-----
MIICGjCCAb+gAwIBAgIFAN6tvu8wCgYIKoZIzj0EAwIwcjELMAkGA1UEBhMCR0Ix
DzANBgNVBAgTBkxvbmRvbjEPMA0GA1UEBxMGTG9uZG9uMQ8wDQYDVQQKEwZHb29n
bGUxDDAKBgNVBAsTA0VuZzEiMCAGA1UEAxMZRmFrZUludGVybWVkaWF0ZUF1dGhv
cml0eTAeFw0xODAyMTMxMTM4MzlaFw0yNTAzMjgxMTM4MzlaMFYxCzAJBgNVBAYT
AkdCMQ8wDQYDVQQIDAZMb25kb24xDzANBgNVBAoMBkdvb2dsZTEMMAoGA1UECwwD
RW5nMRcwFQYDVQQDDA5sZWFmMDEuY3NyLnBlbTBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABOs3TlJFnEbVqLjF7Vi5MCmmcIppoCZcni9uuGsjbIThRjqYNoJEpYoX
i0GCMvQt4Ahbfgc4UvxHVignm+1gi6yjXjBcMB0GA1UdDgQWBBQ/si9B/BGa042m
hYCEhq5+cy5pXTAPBgNVHSMECDAGgAQBAgMEMA8GA1UdDwEB/wQFAwMH+YAwGQYD
VR0RBBIwEIIObGVhZjAxLmNzci5wZW0wCgYIKoZIzj0EAwIDSQAwRgIhALUq8zke
Brd3sq2ogxuDOGReOiVR6VcfAFNy2wgRZT30AiEAoU5dtZqLEG4Voyq92YCRlnwa
T4+R3ESfE/9X8F7OMjQ=
-----END CERTIFICATE-----`
