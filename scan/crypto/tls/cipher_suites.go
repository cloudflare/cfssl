// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/x509"
	"hash"
)

// a keyAgreement implements the client and server side of a TLS key agreement
// protocol by generating and processing key exchange messages.
type keyAgreement interface {
	// On the server side, the first two methods are called in order.

	// In the case that the key agreement protocol doesn't use a
	// ServerKeyExchange message, generateServerKeyExchange can return nil,
	// nil.
	generateServerKeyExchange(*Config, *Certificate, *clientHelloMsg, *serverHelloMsg) (*serverKeyExchangeMsg, error)
	processClientKeyExchange(*Config, *Certificate, *clientKeyExchangeMsg, uint16) ([]byte, error)

	// On the client side, the next two methods are called in order.

	// This method may not be called if the server doesn't send a
	// ServerKeyExchange message.
	processServerKeyExchange(*Config, *clientHelloMsg, *serverHelloMsg, *x509.Certificate, *serverKeyExchangeMsg) error
	generateClientKeyExchange(*Config, *clientHelloMsg, *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error)
}

const (
	// suiteECDH indicates that the cipher suite involves elliptic curve
	// Diffie-Hellman. This means that it should only be selected when the
	// client indicates that it supports ECC with a curve and point format
	// that we're happy with.
	suiteECDHE = 1 << iota
	// suiteECDSA indicates that the cipher suite involves an ECDSA
	// signature and therefore may only be selected when the server's
	// certificate is ECDSA. If this is not set then the cipher suite is
	// RSA based.
	suiteECDSA
	// suiteTLS12 indicates that the cipher suite should only be advertised
	// and accepted when using TLS 1.2.
	suiteTLS12
	// suiteSHA384 indicates that the cipher suite uses SHA384 as the
	// handshake hash.
	suiteSHA384
	// suiteDefaultOff indicates that this cipher suite is not included by
	// default.
	suiteDefaultOff
)

// A cipherSuite is a specific combination of key agreement, cipher and MAC
// function. All cipher suites currently assume RSA key agreement.
type cipherSuite struct {
	id uint16
	// the lengths, in bytes, of the key material needed for each component.
	keyLen int
	macLen int
	ivLen  int
	ka     func(version uint16) keyAgreement
	// flags is a bitmask of the suite* values, above.
	flags  int
	cipher func(key, iv []byte, isRead bool) interface{}
	mac    func(version uint16, macKey []byte) macFunction
	aead   func(key, fixedNonce []byte) aead
}

var cipherSuites = []*cipherSuite{
	// Ciphersuite order is chosen so that ECDHE comes before plain RSA
	// and RC4 comes before AES (because of the Lucky13 attack).
	{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, ecdheRSAKA, suiteECDHE | suiteTLS12, nil, nil, aeadAESGCM},
	{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, ecdheECDSAKA, suiteECDHE | suiteECDSA | suiteTLS12, nil, nil, aeadAESGCM},
	{TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, 32, 0, 4, ecdheRSAKA, suiteECDHE | suiteTLS12 | suiteSHA384, nil, nil, aeadAESGCM},
	{TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, 32, 0, 4, ecdheECDSAKA, suiteECDHE | suiteECDSA | suiteTLS12 | suiteSHA384, nil, nil, aeadAESGCM},
	{TLS_ECDHE_RSA_WITH_RC4_128_SHA, 16, 20, 0, ecdheRSAKA, suiteECDHE | suiteDefaultOff, cipherRC4, macSHA1, nil},
	{TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, 16, 20, 0, ecdheECDSAKA, suiteECDHE | suiteECDSA | suiteDefaultOff, cipherRC4, macSHA1, nil},
	{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, 16, 20, 16, ecdheRSAKA, suiteECDHE, cipherAES, macSHA1, nil},
	{TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, 16, 20, 16, ecdheECDSAKA, suiteECDHE | suiteECDSA, cipherAES, macSHA1, nil},
	{TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, 32, 20, 16, ecdheRSAKA, suiteECDHE, cipherAES, macSHA1, nil},
	{TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, 32, 20, 16, ecdheECDSAKA, suiteECDHE | suiteECDSA, cipherAES, macSHA1, nil},
	{TLS_RSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, rsaKA, suiteTLS12, nil, nil, aeadAESGCM},
	{TLS_RSA_WITH_AES_256_GCM_SHA384, 32, 0, 4, rsaKA, suiteTLS12 | suiteSHA384, nil, nil, aeadAESGCM},
	{TLS_RSA_WITH_RC4_128_SHA, 16, 20, 0, rsaKA, suiteDefaultOff, cipherRC4, macSHA1, nil},
	{TLS_RSA_WITH_AES_128_CBC_SHA, 16, 20, 16, rsaKA, 0, cipherAES, macSHA1, nil},
	{TLS_RSA_WITH_AES_256_CBC_SHA, 32, 20, 16, rsaKA, 0, cipherAES, macSHA1, nil},
	{TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, 24, 20, 8, ecdheRSAKA, suiteECDHE, cipher3DES, macSHA1, nil},
	{TLS_RSA_WITH_3DES_EDE_CBC_SHA, 24, 20, 8, rsaKA, 0, cipher3DES, macSHA1, nil},
}

// A cipherSuiteTLS13 defines only the pair of the AEAD algorithm and hash
// algorithm to be used with HKDF. See RFC 8446, Appendix B.4.
type cipherSuiteTLS13 struct {
	id     uint16
	keyLen int
	aead   func(key, fixedNonce []byte) aead
	hash   crypto.Hash
}

var cipherSuitesTLS13 = []*cipherSuiteTLS13{
	{TLS_AES_128_GCM_SHA256, 16, aeadAESGCMTLS13, crypto.SHA256},
	//{TLS_CHACHA20_POLY1305_SHA256, 32, aeadChaCha20Poly1305, crypto.SHA256},
	{TLS_AES_256_GCM_SHA384, 32, aeadAESGCMTLS13, crypto.SHA384},
}

func cipherRC4(key, iv []byte, isRead bool) interface{} {
	cipher, _ := rc4.NewCipher(key)
	return cipher
}

func cipher3DES(key, iv []byte, isRead bool) interface{} {
	block, _ := des.NewTripleDESCipher(key)
	if isRead {
		return cipher.NewCBCDecrypter(block, iv)
	}
	return cipher.NewCBCEncrypter(block, iv)
}

func cipherAES(key, iv []byte, isRead bool) interface{} {
	block, _ := aes.NewCipher(key)
	if isRead {
		return cipher.NewCBCDecrypter(block, iv)
	}
	return cipher.NewCBCEncrypter(block, iv)
}

// macSHA1 returns a macFunction for the given protocol version.
func macSHA1(version uint16, key []byte) macFunction {
	if version == VersionSSL30 {
		mac := ssl30MAC{
			h:   sha1.New(),
			key: make([]byte, len(key)),
		}
		copy(mac.key, key)
		return mac
	}
	return tls10MAC{hmac.New(sha1.New, key)}
}

type macFunction interface {
	Size() int
	MAC(digestBuf, seq, header, data []byte) []byte
}

type aead interface {
	cipher.AEAD

	// explicitNonceLen returns the number of bytes of explicit nonce
	// included in each record. This is eight for older AEADs and
	// zero for modern ones.
	explicitNonceLen() int
}

const (
	aeadNonceLength   = 12
	noncePrefixLength = 4
)

// prefixNonceAEAD wraps an AEAD and prefixes a fixed portion of the nonce to
// each call.
type prefixNonceAEAD struct {
	// nonce contains the fixed part of the nonce in the first four bytes.
	nonce [aeadNonceLength]byte
	aead  cipher.AEAD
}

func (f *prefixNonceAEAD) NonceSize() int        { return aeadNonceLength - noncePrefixLength }
func (f *prefixNonceAEAD) Overhead() int         { return f.aead.Overhead() }
func (f *prefixNonceAEAD) explicitNonceLen() int { return f.NonceSize() }

func (f *prefixNonceAEAD) Seal(out, nonce, plaintext, additionalData []byte) []byte {
	copy(f.nonce[4:], nonce)
	return f.aead.Seal(out, f.nonce[:], plaintext, additionalData)
}

func (f *prefixNonceAEAD) Open(out, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	copy(f.nonce[4:], nonce)
	return f.aead.Open(out, f.nonce[:], ciphertext, additionalData)
}

// xoredNonceAEAD wraps an AEAD by XORing in a fixed pattern to the nonce
// before each call.
type xorNonceAEAD struct {
	nonceMask [aeadNonceLength]byte
	aead      cipher.AEAD
}

func (f *xorNonceAEAD) NonceSize() int        { return 8 } // 64-bit sequence number
func (f *xorNonceAEAD) Overhead() int         { return f.aead.Overhead() }
func (f *xorNonceAEAD) explicitNonceLen() int { return 0 }

func (f *xorNonceAEAD) Seal(out, nonce, plaintext, additionalData []byte) []byte {
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}
	result := f.aead.Seal(out, f.nonceMask[:], plaintext, additionalData)
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}

	return result
}

func (f *xorNonceAEAD) Open(out, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}
	result, err := f.aead.Open(out, f.nonceMask[:], ciphertext, additionalData)
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}

	return result, err
}

func aeadAESGCM(key, noncePrefix []byte) aead {
	if len(noncePrefix) != noncePrefixLength {
		panic("tls: internal error: wrong nonce length")
	}
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err)
	}

	ret := &prefixNonceAEAD{aead: aead}
	copy(ret.nonce[:], noncePrefix)
	return ret
}

func aeadAESGCMTLS13(key, nonceMask []byte) aead {
	if len(nonceMask) != aeadNonceLength {
		panic("tls: internal error: wrong nonce length")
	}
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err)
	}

	ret := &xorNonceAEAD{aead: aead}
	copy(ret.nonceMask[:], nonceMask)
	return ret
}

// ssl30MAC implements the SSLv3 MAC function, as defined in
// www.mozilla.org/projects/security/pki/nss/ssl/draft302.txt section 5.2.3.1
type ssl30MAC struct {
	h   hash.Hash
	key []byte
}

func (s ssl30MAC) Size() int {
	return s.h.Size()
}

var ssl30Pad1 = [48]byte{0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36}

var ssl30Pad2 = [48]byte{0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c}

func (s ssl30MAC) MAC(digestBuf, seq, header, data []byte) []byte {
	padLength := 48
	if s.h.Size() == 20 {
		padLength = 40
	}

	s.h.Reset()
	s.h.Write(s.key)
	s.h.Write(ssl30Pad1[:padLength])
	s.h.Write(seq)
	s.h.Write(header[:1])
	s.h.Write(header[3:5])
	s.h.Write(data)
	digestBuf = s.h.Sum(digestBuf[:0])

	s.h.Reset()
	s.h.Write(s.key)
	s.h.Write(ssl30Pad2[:padLength])
	s.h.Write(digestBuf)
	return s.h.Sum(digestBuf[:0])
}

// tls10MAC implements the TLS 1.0 MAC function. RFC 2246, section 6.2.3.
type tls10MAC struct {
	h hash.Hash
}

func (s tls10MAC) Size() int {
	return s.h.Size()
}

func (s tls10MAC) MAC(digestBuf, seq, header, data []byte) []byte {
	s.h.Reset()
	s.h.Write(seq)
	s.h.Write(header)
	s.h.Write(data)
	return s.h.Sum(digestBuf[:0])
}

func rsaKA(version uint16) keyAgreement {
	return rsaKeyAgreement{}
}

func ecdheECDSAKA(version uint16) keyAgreement {
	return &ecdheKeyAgreement{
		sigType: signatureECDSA,
		version: version,
	}
}

func ecdheRSAKA(version uint16) keyAgreement {
	return &ecdheKeyAgreement{
		sigType: signatureRSA,
		version: version,
	}
}

// mutualCipherSuite returns a cipherSuite given a list of supported
// ciphersuites and the id requested by the peer.
func mutualCipherSuite(have []uint16, want uint16) *cipherSuite {
	for _, id := range have {
		if id == want {
			for _, suite := range cipherSuites {
				if suite.id == want {
					return suite
				}
			}
			return nil
		}
	}
	return nil
}

func mutualCipherSuiteTLS13(have []uint16, want uint16) *cipherSuiteTLS13 {
	for _, id := range have {
		if id == want {
			return cipherSuiteTLS13ByID(id)
		}
	}
	return nil
}

func cipherSuiteTLS13ByID(id uint16) *cipherSuiteTLS13 {
	for _, cipherSuite := range cipherSuitesTLS13 {
		if cipherSuite.id == id {
			return cipherSuite
		}
	}
	return nil
}

// A list of the possible cipher suite ids. Taken from
// http://www.iana.org/assignments/tls-parameters/tls-parameters.xml
const (
	TLS_RSA_WITH_RC4_128_SHA                uint16 = 0x0005
	TLS_RSA_WITH_3DES_EDE_CBC_SHA           uint16 = 0x000a
	TLS_RSA_WITH_AES_128_CBC_SHA            uint16 = 0x002f
	TLS_RSA_WITH_AES_256_CBC_SHA            uint16 = 0x0035
	TLS_RSA_WITH_AES_128_CBC_SHA256         uint16 = 0x003c
	TLS_RSA_WITH_AES_128_GCM_SHA256         uint16 = 0x009c
	TLS_RSA_WITH_AES_256_GCM_SHA384         uint16 = 0x009d
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA        uint16 = 0xc007
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA    uint16 = 0xc009
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA    uint16 = 0xc00a
	TLS_ECDHE_RSA_WITH_RC4_128_SHA          uint16 = 0xc011
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA     uint16 = 0xc012
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA      uint16 = 0xc013
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA      uint16 = 0xc014
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 uint16 = 0xc023
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256   uint16 = 0xc027
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   uint16 = 0xc02f
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 uint16 = 0xc02b
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384   uint16 = 0xc030
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 uint16 = 0xc02c
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305    uint16 = 0xcca8
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305  uint16 = 0xcca9

	// TLS 1.3 cipher suites.
	TLS_AES_128_GCM_SHA256       uint16 = 0x1301
	TLS_AES_256_GCM_SHA384       uint16 = 0x1302
	TLS_CHACHA20_POLY1305_SHA256 uint16 = 0x1303

	// TLS_FALLBACK_SCSV isn't a standard cipher suite but an indicator
	// that the client is doing version fallback. See
	// https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00.
	TLS_FALLBACK_SCSV uint16 = 0x5600
)
