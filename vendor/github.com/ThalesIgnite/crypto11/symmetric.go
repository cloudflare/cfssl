// Copyright 2018 Thales e-Security, Inc
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package crypto11

import (
	"github.com/miekg/pkcs11"
)

// SymmetricGenParams holds a consistent (key type, mechanism) key generation pair.
type SymmetricGenParams struct {
	// Key type (CKK_...)
	KeyType uint

	// Key generation mechanism (CKM_..._KEY_GEN)
	GenMech uint
}

// SymmetricCipher represents information about a symmetric cipher.
type SymmetricCipher struct {
	// Possible key generation parameters
	// (For HMAC this varies between PKCS#11 implementations.)
	GenParams []SymmetricGenParams

	// Block size in bytes
	BlockSize int

	// True if encryption supported
	Encrypt bool

	// True if MAC supported
	MAC bool

	// ECB mechanism (CKM_..._ECB)
	ECBMech uint

	// CBC mechanism (CKM_..._CBC)
	CBCMech uint

	// CBC mechanism with PKCS#7 padding (CKM_..._CBC)
	CBCPKCSMech uint

	// GCM mechanism (CKM_..._GCM)
	GCMMech uint
}

// CipherAES describes the AES cipher. Use this with the
// GenerateSecretKey... functions.
var CipherAES = SymmetricCipher{
	GenParams: []SymmetricGenParams{
		{
			KeyType: pkcs11.CKK_AES,
			GenMech: pkcs11.CKM_AES_KEY_GEN,
		},
	},
	BlockSize:   16,
	Encrypt:     true,
	MAC:         false,
	ECBMech:     pkcs11.CKM_AES_ECB,
	CBCMech:     pkcs11.CKM_AES_CBC,
	CBCPKCSMech: pkcs11.CKM_AES_CBC_PAD,
	GCMMech:     pkcs11.CKM_AES_GCM,
}

// CipherDES3 describes the three-key triple-DES cipher. Use this with the
// GenerateSecretKey... functions.
var CipherDES3 = SymmetricCipher{
	GenParams: []SymmetricGenParams{
		{
			KeyType: pkcs11.CKK_DES3,
			GenMech: pkcs11.CKM_DES3_KEY_GEN,
		},
	},
	BlockSize:   8,
	Encrypt:     true,
	MAC:         false,
	ECBMech:     pkcs11.CKM_DES3_ECB,
	CBCMech:     pkcs11.CKM_DES3_CBC,
	CBCPKCSMech: pkcs11.CKM_DES3_CBC_PAD,
	GCMMech:     0,
}

// CipherGeneric describes the CKK_GENERIC_SECRET key type. Use this with the
// GenerateSecretKey... functions.
//
// The spec promises that this mechanism can be used to perform HMAC
// operations, although implementations vary;
// CipherHMACSHA1 and so on may give better results.
var CipherGeneric = SymmetricCipher{
	GenParams: []SymmetricGenParams{
		{
			KeyType: pkcs11.CKK_GENERIC_SECRET,
			GenMech: pkcs11.CKM_GENERIC_SECRET_KEY_GEN,
		},
	},
	BlockSize: 64,
	Encrypt:   false,
	MAC:       true,
	ECBMech:   0,
	CBCMech:   0,
	GCMMech:   0,
}

// CipherHMACSHA1 describes the CKK_SHA_1_HMAC key type. Use this with the
// GenerateSecretKey... functions.
var CipherHMACSHA1 = SymmetricCipher{
	GenParams: []SymmetricGenParams{
		{
			KeyType: pkcs11.CKK_SHA_1_HMAC,
			GenMech: CKM_NC_SHA_1_HMAC_KEY_GEN,
		},
		{
			KeyType: pkcs11.CKK_GENERIC_SECRET,
			GenMech: pkcs11.CKM_GENERIC_SECRET_KEY_GEN,
		},
	},
	BlockSize: 64,
	Encrypt:   false,
	MAC:       true,
	ECBMech:   0,
	CBCMech:   0,
	GCMMech:   0,
}

// CipherHMACSHA224 describes the CKK_SHA224_HMAC key type. Use this with the
// GenerateSecretKey... functions.
var CipherHMACSHA224 = SymmetricCipher{
	GenParams: []SymmetricGenParams{
		{
			KeyType: pkcs11.CKK_SHA224_HMAC,
			GenMech: CKM_NC_SHA224_HMAC_KEY_GEN,
		},
		{
			KeyType: pkcs11.CKK_GENERIC_SECRET,
			GenMech: pkcs11.CKM_GENERIC_SECRET_KEY_GEN,
		},
	},
	BlockSize: 64,
	Encrypt:   false,
	MAC:       true,
	ECBMech:   0,
	CBCMech:   0,
	GCMMech:   0,
}

// CipherHMACSHA256 describes the CKK_SHA256_HMAC key type. Use this with the
// GenerateSecretKey... functions.
var CipherHMACSHA256 = SymmetricCipher{
	GenParams: []SymmetricGenParams{
		{
			KeyType: pkcs11.CKK_SHA256_HMAC,
			GenMech: CKM_NC_SHA256_HMAC_KEY_GEN,
		},
		{
			KeyType: pkcs11.CKK_GENERIC_SECRET,
			GenMech: pkcs11.CKM_GENERIC_SECRET_KEY_GEN,
		},
	},
	BlockSize: 64,
	Encrypt:   false,
	MAC:       true,
	ECBMech:   0,
	CBCMech:   0,
	GCMMech:   0,
}

// CipherHMACSHA384 describes the CKK_SHA384_HMAC key type. Use this with the
// GenerateSecretKey... functions.
var CipherHMACSHA384 = SymmetricCipher{
	GenParams: []SymmetricGenParams{
		{
			KeyType: pkcs11.CKK_SHA384_HMAC,
			GenMech: CKM_NC_SHA384_HMAC_KEY_GEN,
		},
		{
			KeyType: pkcs11.CKK_GENERIC_SECRET,
			GenMech: pkcs11.CKM_GENERIC_SECRET_KEY_GEN,
		},
	},
	BlockSize: 64,
	Encrypt:   false,
	MAC:       true,
	ECBMech:   0,
	CBCMech:   0,
	GCMMech:   0,
}

// CipherHMACSHA512 describes the CKK_SHA512_HMAC key type. Use this with the
// GenerateSecretKey... functions.
var CipherHMACSHA512 = SymmetricCipher{
	GenParams: []SymmetricGenParams{
		{
			KeyType: pkcs11.CKK_SHA512_HMAC,
			GenMech: CKM_NC_SHA512_HMAC_KEY_GEN,
		},
		{
			KeyType: pkcs11.CKK_GENERIC_SECRET,
			GenMech: pkcs11.CKM_GENERIC_SECRET_KEY_GEN,
		},
	},
	BlockSize: 128,
	Encrypt:   false,
	MAC:       true,
	ECBMech:   0,
	CBCMech:   0,
	GCMMech:   0,
}

// Ciphers is a map of PKCS#11 key types (CKK_...) to symmetric cipher information.
var Ciphers = map[int]*SymmetricCipher{
	pkcs11.CKK_AES:            &CipherAES,
	pkcs11.CKK_DES3:           &CipherDES3,
	pkcs11.CKK_GENERIC_SECRET: &CipherGeneric,
	pkcs11.CKK_SHA_1_HMAC:     &CipherHMACSHA1,
	pkcs11.CKK_SHA224_HMAC:    &CipherHMACSHA224,
	pkcs11.CKK_SHA256_HMAC:    &CipherHMACSHA256,
	pkcs11.CKK_SHA384_HMAC:    &CipherHMACSHA384,
	pkcs11.CKK_SHA512_HMAC:    &CipherHMACSHA512,
}

// PKCS11SecretKey contains a reference to a loaded PKCS#11 symmetric key object.
//
// A *PKCS11SecretKey implements the cipher.Block interface, allowing it be used
// as the argument to cipher.NewCBCEncrypter and similar methods.
// For bulk operation this is very inefficient;
// using NewCBCEncrypterCloser, NewCBCEncrypter or NewCBC from this package is
// much faster.
type PKCS11SecretKey struct {
	PKCS11Object

	// Symmetric cipher information
	Cipher *SymmetricCipher
}

// Key generation -------------------------------------------------------------

// GenerateSecretKey creates an secret key of given length and type.
//
// The key will have a random label and ID.
func GenerateSecretKey(bits int, cipher *SymmetricCipher) (*PKCS11SecretKey, error) {
	return GenerateSecretKeyOnSlot(instance.slot, nil, nil, bits, cipher)
}

// GenerateSecretKeyOnSlot creates as symmetric key on a specified slot
//
// Either or both label and/or id can be nil, in which case random values will be generated.
func GenerateSecretKeyOnSlot(slot uint, id []byte, label []byte, bits int, cipher *SymmetricCipher) (*PKCS11SecretKey, error) {
	var k *PKCS11SecretKey
	var err error
	if err = ensureSessions(instance, slot); err != nil {
		return nil, err
	}
	err = withSession(slot, func(session *PKCS11Session) error {
		k, err = GenerateSecretKeyOnSession(session, slot, id, label, bits, cipher)
		return err
	})
	return k, err
}

// GenerateSecretKeyOnSession creates a symmetric key of given type and
// length, on a specified session.
//
// Either or both label and/or id can be nil, in which case random values will be generated.
func GenerateSecretKeyOnSession(session *PKCS11Session, slot uint, id []byte, label []byte, bits int, cipher *SymmetricCipher) (key *PKCS11SecretKey, err error) {
	// TODO refactor with the other key generation implementations
	if label == nil {
		if label, err = generateKeyLabel(); err != nil {
			return nil, err
		}
	}
	if id == nil {
		if id, err = generateKeyLabel(); err != nil {
			return nil, err
		}
	}
	var privHandle pkcs11.ObjectHandle
	// CKK_*_HMAC exists but there is no specific corresponding CKM_*_KEY_GEN
	// mechanism. Therefore we attempt both CKM_GENERIC_SECRET_KEY_GEN and
	// vendor-specific mechanisms.
	for _, genMech := range cipher.GenParams {
		secretKeyTemplate := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, genMech.KeyType),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, cipher.MAC),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, cipher.MAC),
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, cipher.Encrypt),
			pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, cipher.Encrypt),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		}
		if bits > 0 {
			secretKeyTemplate = append(secretKeyTemplate, pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, bits/8))
		}
		mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(genMech.GenMech, nil)}
		privHandle, err = session.Ctx.GenerateKey(session.Handle, mech, secretKeyTemplate)
		if err == nil {
			break
		}
		// nShield returns this if if doesn't like the CKK/CKM combination.
		if e, ok := err.(pkcs11.Error); ok && e == pkcs11.CKR_TEMPLATE_INCONSISTENT {
			continue
		}
		if err != nil {
			return
		}
	}
	if err != nil {
		return
	}
	key = &PKCS11SecretKey{PKCS11Object{privHandle, slot}, cipher}
	return
}
