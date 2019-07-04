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

	pkcs11 "github.com/miekg/pkcs11"
)

// Identify returns the ID and label for a PKCS#11 object.
//
// Either of these values may be used to retrieve the key for later use.
func (object *PKCS11Object) Identify() (id []byte, label []byte, err error) {
	a := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
	}
	if err = withSession(object.Slot, func(session *PKCS11Session) error {
		a, err = instance.ctx.GetAttributeValue(session.Handle, object.Handle, a)
		return err
	}); err != nil {
		return nil, nil, err
	}
	return a[0].Value, a[1].Value, nil
}

// Find a key object.  For asymmetric keys this only finds one half so
// callers will call it twice.
func findKey(session *PKCS11Session, id []byte, label []byte, keyclass uint, keytype uint) (obj pkcs11.ObjectHandle, err error) {
	var handles []pkcs11.ObjectHandle
	var template []*pkcs11.Attribute
	if keyclass != ^uint(0) {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_CLASS, keyclass))
	}
	if keytype != ^uint(0) {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, keytype))
	}
	if id != nil {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_ID, id))
	}
	if label != nil {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, label))
	}
	if err = session.Ctx.FindObjectsInit(session.Handle, template); err != nil {
		return 0, err
	}
	defer func() {
		finalErr := session.Ctx.FindObjectsFinal(session.Handle)
		if err == nil {
			err = finalErr
		}
	}()
	if handles, _, err = session.Ctx.FindObjects(session.Handle, 1); err != nil {
		return 0, err
	}
	if len(handles) == 0 {
		return 0, ErrKeyNotFound
	}
	return handles[0], nil
}

// FindKeyPair retrieves a previously created asymmetric key.
//
// Either (but not both) of id and label may be nil, in which case they are ignored.
func FindKeyPair(id []byte, label []byte) (crypto.PrivateKey, error) {
	return FindKeyPairOnSlot(instance.slot, id, label)
}

// FindKeyPairOnSlot retrieves a previously created asymmetric key, using a specified slot.
//
// Either (but not both) of id and label may be nil, in which case they are ignored.
func FindKeyPairOnSlot(slot uint, id []byte, label []byte) (crypto.PrivateKey, error) {
	var err error
	var k crypto.PrivateKey
	if err = ensureSessions(instance, slot); err != nil {
		return nil, err
	}
	err = withSession(slot, func(session *PKCS11Session) error {
		k, err = FindKeyPairOnSession(session, slot, id, label)
		return err
	})
	return k, err
}

// FindKeyPairOnSession retrieves a previously created asymmetric key, using a specified session.
//
// Either (but not both) of id and label may be nil, in which case they are ignored.
func FindKeyPairOnSession(session *PKCS11Session, slot uint, id []byte, label []byte) (crypto.PrivateKey, error) {
	var err error
	var privHandle, pubHandle pkcs11.ObjectHandle
	var pub crypto.PublicKey

	if privHandle, err = findKey(session, id, label, pkcs11.CKO_PRIVATE_KEY, ^uint(0)); err != nil {
		return nil, err
	}
	attributes := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, 0),
	}
	if attributes, err = session.Ctx.GetAttributeValue(session.Handle, privHandle, attributes); err != nil {
		return nil, err
	}
	keyType := bytesToUlong(attributes[0].Value)
	if pubHandle, err = findKey(session, id, label, pkcs11.CKO_PUBLIC_KEY, keyType); err != nil {
		return nil, err
	}
	switch keyType {
	case pkcs11.CKK_DSA:
		if pub, err = exportDSAPublicKey(session, pubHandle); err != nil {
			return nil, err
		}
		return &PKCS11PrivateKeyDSA{PKCS11PrivateKey{PKCS11Object{privHandle, slot}, pub}}, nil
	case pkcs11.CKK_RSA:
		if pub, err = exportRSAPublicKey(session, pubHandle); err != nil {
			return nil, err
		}
		return &PKCS11PrivateKeyRSA{PKCS11PrivateKey{PKCS11Object{privHandle, slot}, pub}}, nil
	case pkcs11.CKK_ECDSA:
		if pub, err = exportECDSAPublicKey(session, pubHandle); err != nil {
			return nil, err
		}
		return &PKCS11PrivateKeyECDSA{PKCS11PrivateKey{PKCS11Object{privHandle, slot}, pub}}, nil
	default:
		return nil, ErrUnsupportedKeyType
	}
}

// Public returns the public half of a private key.
//
// This partially implements the go.crypto.Signer and go.crypto.Decrypter interfaces for
// PKCS11PrivateKey. (The remains of the implementation is in the
// key-specific types.)
func (signer PKCS11PrivateKey) Public() crypto.PublicKey {
	return signer.PubKey
}

// FindKey retrieves a previously created symmetric key.
//
// Either (but not both) of id and label may be nil, in which case they are ignored.
func FindKey(id []byte, label []byte) (*PKCS11SecretKey, error) {
	return FindKeyOnSlot(instance.slot, id, label)
}

// FindKeyOnSlot retrieves a previously created symmetric key, using a specified slot.
//
// Either (but not both) of id and label may be nil, in which case they are ignored.
func FindKeyOnSlot(slot uint, id []byte, label []byte) (*PKCS11SecretKey, error) {
	var err error
	var k *PKCS11SecretKey
	if err = ensureSessions(instance, slot); err != nil {
		return nil, err
	}
	err = withSession(slot, func(session *PKCS11Session) error {
		k, err = FindKeyOnSession(session, slot, id, label)
		return err
	})
	return k, err
}

// FindKeyOnSession retrieves a previously created symmetric key, using a specified session.
//
// Either (but not both) of id and label may be nil, in which case they are ignored.
func FindKeyOnSession(session *PKCS11Session, slot uint, id []byte, label []byte) (key *PKCS11SecretKey, err error) {
	var privHandle pkcs11.ObjectHandle
	if privHandle, err = findKey(session, id, label, pkcs11.CKO_SECRET_KEY, ^uint(0)); err != nil {
		return
	}
	attributes := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, 0),
	}
	if attributes, err = session.Ctx.GetAttributeValue(session.Handle, privHandle, attributes); err != nil {
		return
	}
	if cipher, ok := Ciphers[int(bytesToUlong(attributes[0].Value))]; ok {
		key = &PKCS11SecretKey{PKCS11Object{privHandle, slot}, cipher}
	} else {
		err = ErrUnsupportedKeyType
		return
	}
	return
}
