// Copyright 2016, 2017 Thales e-Security, Inc
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
	"crypto"
	"crypto/rsa"
	"errors"
	"io"
	"math/big"
	"unsafe"

	pkcs11 "github.com/miekg/pkcs11"
)

// ErrMalformedRSAKey is returned when an RSA key is not in a suitable form.
//
// Currently this means that the public exponent is either bigger than
// 32 bits, or less than 2.
var ErrMalformedRSAKey = errors.New("crypto11/rsa: malformed RSA key")

// ErrUnrecognizedRSAOptions is returned when unrecognized options
// structures are pased to Sign or Decrypt.
var ErrUnrecognizedRSAOptions = errors.New("crypto11/rsa: unrecognized RSA options type")

// ErrUnsupportedRSAOptions is returned when an unsupported RSA option is requested.
//
// Currently this means a nontrivial SessionKeyLen when decrypting; or
// an unsupported hash function; or crypto.rsa.PSSSaltLengthAuto was
// requested.
var ErrUnsupportedRSAOptions = errors.New("crypto11/rsa: unsupported RSA option value")

// PKCS11PrivateKeyRSA contains a reference to a loaded PKCS#11 RSA private key object.
type PKCS11PrivateKeyRSA struct {
	PKCS11PrivateKey
}

// Export the public key corresponding to a private RSA key.
func exportRSAPublicKey(session *PKCS11Session, pubHandle pkcs11.ObjectHandle) (crypto.PublicKey, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	}
	exported, err := session.Ctx.GetAttributeValue(session.Handle, pubHandle, template)
	if err != nil {
		return nil, err
	}
	var modulus = new(big.Int)
	modulus.SetBytes(exported[0].Value)
	var bigExponent = new(big.Int)
	bigExponent.SetBytes(exported[1].Value)
	if bigExponent.BitLen() > 32 {
		return nil, ErrMalformedRSAKey
	}
	if bigExponent.Sign() < 1 {
		return nil, ErrMalformedRSAKey
	}
	exponent := int(bigExponent.Uint64())
	result := rsa.PublicKey{
		N: modulus,
		E: exponent,
	}
	if result.E < 2 {
		return nil, ErrMalformedRSAKey
	}
	return &result, nil
}

// GenerateRSAKeyPair creates an RSA private key of given length.
//
// The key will have a random label and ID.
//
// RSA private keys are generated with both sign and decrypt
// permissions, and a public exponent of 65537.
func GenerateRSAKeyPair(bits int) (*PKCS11PrivateKeyRSA, error) {
	return GenerateRSAKeyPairOnSlot(instance.slot, nil, nil, bits)
}

// GenerateRSAKeyPairOnSlot creates a RSA private key on a specified slot
//
// Either or both label and/or id can be nil, in which case random values will be generated.
func GenerateRSAKeyPairOnSlot(slot uint, id []byte, label []byte, bits int) (*PKCS11PrivateKeyRSA, error) {
	var k *PKCS11PrivateKeyRSA
	var err error
	if err = ensureSessions(instance, slot); err != nil {
		return nil, err
	}
	err = withSession(slot, func(session *PKCS11Session) error {
		k, err = GenerateRSAKeyPairOnSession(session, slot, id, label, bits)
		return err
	})
	return k, err
}

// GenerateRSAKeyPairOnSession creates an RSA private key of given length, on a specified session.
//
// Either or both label and/or id can be nil, in which case random values will be generated.
//
// RSA private keys are generated with both sign and decrypt
// permissions, and a public exponent of 65537.
func GenerateRSAKeyPairOnSession(session *PKCS11Session, slot uint, id []byte, label []byte, bits int) (*PKCS11PrivateKeyRSA, error) {
	var err error
	var pub crypto.PublicKey

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
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, bits),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)}
	pubHandle, privHandle, err := session.Ctx.GenerateKeyPair(session.Handle,
		mech,
		publicKeyTemplate,
		privateKeyTemplate)
	if err != nil {
		return nil, err
	}
	if pub, err = exportRSAPublicKey(session, pubHandle); err != nil {
		return nil, err
	}
	priv := PKCS11PrivateKeyRSA{PKCS11PrivateKey{PKCS11Object{privHandle, slot}, pub}}
	return &priv, nil
}

// Decrypt decrypts a message using a RSA key.
//
// This completes the implemention of crypto.Decrypter for PKCS11PrivateKeyRSA.
//
// Note that the SessionKeyLen option (for PKCS#1v1.5 decryption) is not supported.
//
// The underlying PKCS#11 implementation may impose further restrictions.
func (priv *PKCS11PrivateKeyRSA) Decrypt(rand io.Reader, ciphertext []byte, options crypto.DecrypterOpts) (plaintext []byte, err error) {
	err = withSession(priv.Slot, func(session *PKCS11Session) error {
		if options == nil {
			plaintext, err = decryptPKCS1v15(session, priv, ciphertext, 0)
		} else {
			switch o := options.(type) {
			case *rsa.PKCS1v15DecryptOptions:
				plaintext, err = decryptPKCS1v15(session, priv, ciphertext, o.SessionKeyLen)
			case *rsa.OAEPOptions:
				plaintext, err = decryptOAEP(session, priv, ciphertext, o.Hash, o.Label)
			default:
				err = ErrUnsupportedRSAOptions
			}
		}
		return err
	})
	return plaintext, err
}

func decryptPKCS1v15(session *PKCS11Session, key *PKCS11PrivateKeyRSA, ciphertext []byte, sessionKeyLen int) ([]byte, error) {
	if sessionKeyLen != 0 {
		return nil, ErrUnsupportedRSAOptions
	}
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}
	if err := session.Ctx.DecryptInit(session.Handle, mech, key.Handle); err != nil {
		return nil, err
	}
	return session.Ctx.Decrypt(session.Handle, ciphertext)
}

func decryptOAEP(session *PKCS11Session, key *PKCS11PrivateKeyRSA, ciphertext []byte, hashFunction crypto.Hash, label []byte) ([]byte, error) {
	var err error
	var hMech, mgf, sourceData, sourceDataLen uint
	if hMech, mgf, _, err = hashToPKCS11(hashFunction); err != nil {
		return nil, err
	}
	if label != nil && len(label) > 0 {
		sourceData = uint(uintptr(unsafe.Pointer(&label[0])))
		sourceDataLen = uint(len(label))
	}
	parameters := concat(ulongToBytes(hMech),
		ulongToBytes(mgf),
		ulongToBytes(pkcs11.CKZ_DATA_SPECIFIED),
		ulongToBytes(sourceData),
		ulongToBytes(sourceDataLen))
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, parameters)}
	if err = session.Ctx.DecryptInit(session.Handle, mech, key.Handle); err != nil {
		return nil, err
	}
	return session.Ctx.Decrypt(session.Handle, ciphertext)
}

func hashToPKCS11(hashFunction crypto.Hash) (uint, uint, uint, error) {
	switch hashFunction {
	case crypto.SHA1:
		return pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1, 20, nil
	case crypto.SHA224:
		return pkcs11.CKM_SHA224, pkcs11.CKG_MGF1_SHA224, 28, nil
	case crypto.SHA256:
		return pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256, 32, nil
	case crypto.SHA384:
		return pkcs11.CKM_SHA384, pkcs11.CKG_MGF1_SHA384, 48, nil
	case crypto.SHA512:
		return pkcs11.CKM_SHA512, pkcs11.CKG_MGF1_SHA512, 64, nil
	default:
		return 0, 0, 0, ErrUnsupportedRSAOptions
	}
}

func signPSS(session *PKCS11Session, key *PKCS11PrivateKeyRSA, digest []byte, opts *rsa.PSSOptions) ([]byte, error) {
	var hMech, mgf, hLen, sLen uint
	var err error
	if hMech, mgf, hLen, err = hashToPKCS11(opts.Hash); err != nil {
		return nil, err
	}
	switch opts.SaltLength {
	case rsa.PSSSaltLengthAuto: // parseltongue constant
		// TODO we could (in principle) work out the biggest
		// possible size from the key, but until someone has
		// the effort to do that...
		return nil, ErrUnsupportedRSAOptions
	case rsa.PSSSaltLengthEqualsHash:
		sLen = hLen
	default:
		sLen = uint(opts.SaltLength)
	}
	// TODO this is pretty horrible, maybe the PKCS#11 wrapper
	// could be improved to help us out here
	parameters := concat(ulongToBytes(hMech),
		ulongToBytes(mgf),
		ulongToBytes(sLen))
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_PSS, parameters)}
	if err = session.Ctx.SignInit(session.Handle, mech, key.Handle); err != nil {
		return nil, err
	}
	return session.Ctx.Sign(session.Handle, digest)
}

var pkcs1Prefix = map[crypto.Hash][]byte{
	crypto.SHA1:   []byte{0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224: []byte{0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256: []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384: []byte{0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512: []byte{0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}

func signPKCS1v15(session *PKCS11Session, key *PKCS11PrivateKeyRSA, digest []byte, hash crypto.Hash) (signature []byte, err error) {
	/* Calculate T for EMSA-PKCS1-v1_5. */
	oid := pkcs1Prefix[hash]
	T := make([]byte, len(oid)+len(digest))
	copy(T[0:len(oid)], oid)
	copy(T[len(oid):], digest)
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}
	err = session.Ctx.SignInit(session.Handle, mech, key.Handle)
	if err == nil {
		signature, err = session.Ctx.Sign(session.Handle, T)
	}
	return
}

// Sign signs a message using a RSA key.
//
// This completes the implemention of crypto.Signer for PKCS11PrivateKeyRSA.
//
// PKCS#11 expects to pick its own random data where necessary for signatures, so the rand argument is ignored.
//
// Note that (at present) the crypto.rsa.PSSSaltLengthAuto option is
// not supported. The caller must either use
// crypto.rsa.PSSSaltLengthEqualsHash (recommended) or pass an
// explicit salt length. Moreover the underlying PKCS#11
// implementation may impose further restrictions.
func (priv *PKCS11PrivateKeyRSA) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if err != nil {
		return nil, err
	}
	err = withSession(priv.Slot, func(session *PKCS11Session) error {
		switch opts.(type) {
		case *rsa.PSSOptions:
			signature, err = signPSS(session, priv, digest, opts.(*rsa.PSSOptions))
		default: /* PKCS1-v1_5 */
			signature, err = signPKCS1v15(session, priv, digest, opts.HashFunc())
		}
		return err
	})
	return signature, err
}

// Validate checks an RSA key.
//
// Since the private key material is not normally available only very
// limited validation is possible. (The underlying PKCS#11
// implementation may perform stricter checking.)
func (priv *PKCS11PrivateKeyRSA) Validate() error {
	pub := priv.PubKey.(*rsa.PublicKey)
	if pub.E < 2 {
		return ErrMalformedRSAKey
	}
	// The software implementation actively rejects 'large' public
	// exponents, in order to simplify its own implementation.
	// Here, instead, we expect the PKCS#11 library to enforce its
	// own preferred constraints, whatever they might be.
	return nil
}
