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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"

	pkcs11 "github.com/miekg/pkcs11"
)

// ErrUnsupportedEllipticCurve is returned when an elliptic curve
// unsupported by crypto11 is specified.  Note that the error behavior
// for an elliptic curve unsupported by the underlying PKCS#11
// implementation will be different.
var ErrUnsupportedEllipticCurve = errors.New("crypto11/ecdsa: unsupported elliptic curve")

// ErrMalformedPoint is returned when crypto.elliptic.Unmarshal cannot
// decode a point.
var ErrMalformedPoint = errors.New("crypto11/ecdsa: malformed elliptic curve point")

// PKCS11PrivateKeyECDSA contains a reference to a loaded PKCS#11 ECDSA private key object.
type PKCS11PrivateKeyECDSA struct {
	PKCS11PrivateKey
}

// Information about an Elliptic Curve
type curveInfo struct {
	// ASN.1 marshaled OID
	oid []byte

	// Curve definition in Go form
	curve elliptic.Curve
}

// ASN.1 marshal some value and panic on error
func mustMarshal(val interface{}) []byte {
	if b, err := asn1.Marshal(val); err != nil {
		panic(err)
	} else {
		return b
	}
}

// Note: some of these are outside what crypto/elliptic currently
// knows about. So I'm making a (reasonable) assumption about what
// they will be called if they are either added or if someone
// specifies them explicitly.
//
// For public key export, the curve has to be a known one, otherwise
// you're stuffed. This is probably better fixed by adding well-known
// curves to crypto/elliptic rather than having a private copy here.
var wellKnownCurves = map[string]curveInfo{
	"P-192": {
		mustMarshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 1}),
		nil,
	},
	"P-224": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 33}),
		elliptic.P224(),
	},
	"P-256": {
		mustMarshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}),
		elliptic.P256(),
	},
	"P-384": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 34}),
		elliptic.P384(),
	},
	"P-521": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 35}),
		elliptic.P521(),
	},

	"K-163": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 1}),
		nil,
	},
	"K-233": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 26}),
		nil,
	},
	"K-283": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 16}),
		nil,
	},
	"K-409": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 36}),
		nil,
	},
	"K-571": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 38}),
		nil,
	},

	"B-163": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 15}),
		nil,
	},
	"B-233": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 27}),
		nil,
	},
	"B-283": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 17}),
		nil,
	},
	"B-409": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 37}),
		nil,
	},
	"B-571": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 39}),
		nil,
	},
}

func marshalEcParams(c elliptic.Curve) ([]byte, error) {
	if ci, ok := wellKnownCurves[c.Params().Name]; ok {
		return ci.oid, nil
	}
	// TODO use ANSI X9.62 ECParameters representation instead
	return nil, ErrUnsupportedEllipticCurve
}

func unmarshalEcParams(b []byte) (elliptic.Curve, error) {
	// See if it's a well-known curve
	for _, ci := range wellKnownCurves {
		if bytes.Compare(b, ci.oid) == 0 {
			if ci.curve != nil {
				return ci.curve, nil
			}
			return nil, ErrUnsupportedEllipticCurve
		}
	}
	// TODO try ANSI X9.62 ECParameters representation
	return nil, ErrUnsupportedEllipticCurve
}

func unmarshalEcPoint(b []byte, c elliptic.Curve) (x *big.Int, y *big.Int, err error) {
	// Decoding an octet string in isolation seems to be too hard
	// with encoding.asn1, so we do it manually. Look away now.
	if b[0] != 4 {
		return nil, nil, ErrMalformedDER
	}
	var l, r int
	if b[1] < 128 {
		l = int(b[1])
		r = 2
	} else {
		ll := int(b[1] & 127)
		if ll > 2 { // unreasonably long
			return nil, nil, ErrMalformedDER
		}
		l = 0
		for i := int(0); i < ll; i++ {
			l = 256*l + int(b[2+i])
		}
		r = ll + 2
	}
	if r+l > len(b) {
		return nil, nil, ErrMalformedDER
	}
	pointBytes := b[r:]
	x, y = elliptic.Unmarshal(c, pointBytes)
	if x == nil || y == nil {
		err = ErrMalformedPoint
	}
	return
}

// Export the public key corresponding to a private ECDSA key.
func exportECDSAPublicKey(session *PKCS11Session, pubHandle pkcs11.ObjectHandle) (crypto.PublicKey, error) {
	var err error
	var attributes []*pkcs11.Attribute
	var pub ecdsa.PublicKey
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ECDSA_PARAMS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	}
	if attributes, err = session.Ctx.GetAttributeValue(session.Handle, pubHandle, template); err != nil {
		return nil, err
	}
	if pub.Curve, err = unmarshalEcParams(attributes[0].Value); err != nil {
		return nil, err
	}
	if pub.X, pub.Y, err = unmarshalEcPoint(attributes[1].Value, pub.Curve); err != nil {
		return nil, err
	}
	return &pub, nil
}

// GenerateECDSAKeyPair creates an ECDSA private key using curve c.
//
// The key will have a random label and ID.
//
// Only a limited set of named elliptic curves are supported. The
// underlying PKCS#11 implementation may impose further restrictions.
func GenerateECDSAKeyPair(c elliptic.Curve) (*PKCS11PrivateKeyECDSA, error) {
	return GenerateECDSAKeyPairOnSlot(instance.slot, nil, nil, c)
}

// GenerateECDSAKeyPairOnSlot creates an ECDSA private key using curve c, on a specified slot.
//
// label and/or id can be nil, in which case random values will be generated.
//
// Only a limited set of named elliptic curves are supported. The
// underlying PKCS#11 implementation may impose further restrictions.
func GenerateECDSAKeyPairOnSlot(slot uint, id []byte, label []byte, c elliptic.Curve) (*PKCS11PrivateKeyECDSA, error) {
	var k *PKCS11PrivateKeyECDSA
	var err error
	if err = ensureSessions(instance, slot); err != nil {
		return nil, err
	}
	err = withSession(slot, func(session *PKCS11Session) error {
		k, err = GenerateECDSAKeyPairOnSession(session, slot, id, label, c)
		return err
	})
	return k, err
}

// GenerateECDSAKeyPairOnSession creates an ECDSA private key using curve c, using a specified session.
//
// label and/or id can be nil, in which case random values will be generated.
//
// Only a limited set of named elliptic curves are supported. The
// underlying PKCS#11 implementation may impose further restrictions.
func GenerateECDSAKeyPairOnSession(session *PKCS11Session, slot uint, id []byte, label []byte, c elliptic.Curve) (*PKCS11PrivateKeyECDSA, error) {
	var err error
	var parameters []byte
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
	if parameters, err = marshalEcParams(c); err != nil {
		return nil, err
	}
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_ECDSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_ECDSA_PARAMS, parameters),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA_KEY_PAIR_GEN, nil)}
	pubHandle, privHandle, err := session.Ctx.GenerateKeyPair(session.Handle,
		mech,
		publicKeyTemplate,
		privateKeyTemplate)
	if err != nil {
		return nil, err
	}
	if pub, err = exportECDSAPublicKey(session, pubHandle); err != nil {
		return nil, err
	}
	priv := PKCS11PrivateKeyECDSA{PKCS11PrivateKey{PKCS11Object{privHandle, slot}, pub}}
	return &priv, nil
}

// Sign signs a message using an ECDSA key.
//
// This completes the implemention of crypto.Signer for PKCS11PrivateKeyECDSA.
//
// PKCS#11 expects to pick its own random data where necessary for signatures, so the rand argument is ignored.
//
// The return value is a DER-encoded byteblock.
func (signer *PKCS11PrivateKeyECDSA) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return dsaGeneric(signer.Slot, signer.Handle, pkcs11.CKM_ECDSA, digest)
}
