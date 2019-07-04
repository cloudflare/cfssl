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
	"crypto/cipher"
	"errors"
	"fmt"
	"github.com/miekg/pkcs11"
)

// cipher.AEAD ----------------------------------------------------------

const (
	// PaddingNone represents a block cipher with no padding. (See NewCBC.)
	PaddingNone = iota

	// PaddingPKCS represents a block cipher used with PKCS#7 padding. (See NewCBC.)
	PaddingPKCS
)

type genericAead struct {
	key *PKCS11SecretKey

	overhead int

	nonceSize int

	makeMech func(nonce []byte, additionalData []byte) ([]*pkcs11.Mechanism, error)
}

// NewGCM returns a given cipher wrapped in Galois Counter Mode, with the standard
// nonce length.
//
// This depends on the HSM supporting the CKM_*_GCM mechanism. If it is not supported
// then you must use cipher.NewGCM; it will be slow.
func (key *PKCS11SecretKey) NewGCM() (g cipher.AEAD, err error) {
	if key.Cipher.GCMMech == 0 {
		err = fmt.Errorf("GCM not implemented for key type %#x", key.Cipher.GenParams[0].KeyType)
		return
	}
	g = genericAead{
		key:       key,
		overhead:  16,
		nonceSize: 12,
		makeMech: func(nonce []byte, additionalData []byte) (mech []*pkcs11.Mechanism, error error) {
			params := pkcs11.NewGCMParams(nonce, additionalData, 16*8 /*bits*/)
			mech = []*pkcs11.Mechanism{pkcs11.NewMechanism(key.Cipher.GCMMech, params)}
			return
		},
	}
	return
}

// NewCBC returns a given cipher wrapped in CBC mode.
//
// Despite the cipher.AEAD return type, there is no support for additional data and no authentication.
// This method exists to provide a convenient way to do bulk (possibly padded) CBC encryption.
// Think carefully before passing the cipher.AEAD to any consumer that expects authentication.
func (key *PKCS11SecretKey) NewCBC(paddingMode int) (g cipher.AEAD, err error) {
	g = genericAead{
		key:       key,
		overhead:  0,
		nonceSize: key.BlockSize(),
		makeMech: func(nonce []byte, additionalData []byte) (mech []*pkcs11.Mechanism, error error) {
			if len(additionalData) > 0 {
				err = errors.New("additional data not supported for CBC mode")
			}
			var pkcsMech uint
			switch paddingMode {
			case PaddingNone:
				pkcsMech = key.Cipher.CBCMech
			case PaddingPKCS:
				pkcsMech = key.Cipher.CBCPKCSMech
			default:
				err = errors.New("unrecognized padding mode")
				return
			}
			if pkcsMech == 0 {
				err = errors.New("unsupported padding mode")
				return
			}
			mech = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcsMech, nonce)}
			return
		},
	}
	return
}

func (g genericAead) NonceSize() int {
	return g.nonceSize
}

func (g genericAead) Overhead() int {
	return g.overhead
}

func (g genericAead) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	var result []byte
	if err := withSession(g.key.Slot, func(session *PKCS11Session) (err error) {
		var mech []*pkcs11.Mechanism
		if mech, err = g.makeMech(nonce, additionalData); err != nil {
			return
		}
		if err = session.Ctx.EncryptInit(session.Handle, mech, g.key.Handle); err != nil {
			err = fmt.Errorf("C_EncryptInit: %v", err)
			return
		}
		if result, err = session.Ctx.Encrypt(session.Handle, plaintext); err != nil {
			err = fmt.Errorf("C_Encrypt: %v", err)
			return
		}
		return
	}); err != nil {
		panic(err)
	} else {
		dst = append(dst, result...)
	}
	return dst
}

func (g genericAead) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	var result []byte
	if err := withSession(g.key.Slot, func(session *PKCS11Session) (err error) {
		var mech []*pkcs11.Mechanism
		if mech, err = g.makeMech(nonce, additionalData); err != nil {
			return
		}
		if err = session.Ctx.DecryptInit(session.Handle, mech, g.key.Handle); err != nil {
			err = fmt.Errorf("C_DecryptInit: %v", err)
			return
		}
		if result, err = session.Ctx.Decrypt(session.Handle, ciphertext); err != nil {
			err = fmt.Errorf("C_Decrypt: %v", err)
			return
		}
		return
	}); err != nil {
		return nil, err
	}
	dst = append(dst, result...)
	return dst, nil
}
