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
	"crypto/dsa"
	"io"
	"math/big"

	pkcs11 "github.com/miekg/pkcs11"
)

// PKCS11PrivateKeyDSA contains a reference to a loaded PKCS#11 DSA private key object.
type PKCS11PrivateKeyDSA struct {
	PKCS11PrivateKey
}

// Export the public key corresponding to a private DSA key.
func exportDSAPublicKey(session *PKCS11Session, pubHandle pkcs11.ObjectHandle) (crypto.PublicKey, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_PRIME, nil),
		pkcs11.NewAttribute(pkcs11.CKA_SUBPRIME, nil),
		pkcs11.NewAttribute(pkcs11.CKA_BASE, nil),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	}
	exported, err := session.Ctx.GetAttributeValue(session.Handle, pubHandle, template)
	if err != nil {
		return nil, err
	}
	var p, q, g, y big.Int
	p.SetBytes(exported[0].Value)
	q.SetBytes(exported[1].Value)
	g.SetBytes(exported[2].Value)
	y.SetBytes(exported[3].Value)
	result := dsa.PublicKey{
		Parameters: dsa.Parameters{
			P: &p,
			Q: &q,
			G: &g,
		},
		Y: &y,
	}
	return &result, nil
}

// GenerateDSAKeyPair creates a DSA private key on the default slot
//
// The key will have a random label and ID.
func GenerateDSAKeyPair(params *dsa.Parameters) (*PKCS11PrivateKeyDSA, error) {
	return GenerateDSAKeyPairOnSlot(instance.slot, nil, nil, params)
}

// GenerateDSAKeyPairOnSlot creates a DSA private key on a specified slot
//
// Either or both label and/or id can be nil, in which case random values will be generated.
func GenerateDSAKeyPairOnSlot(slot uint, id []byte, label []byte, params *dsa.Parameters) (*PKCS11PrivateKeyDSA, error) {
	var k *PKCS11PrivateKeyDSA
	var err error
	if err = ensureSessions(instance, slot); err != nil {
		return nil, err
	}
	err = withSession(slot, func(session *PKCS11Session) error {
		k, err = GenerateDSAKeyPairOnSession(session, slot, id, label, params)
		return err
	})
	return k, err
}

// GenerateDSAKeyPairOnSession creates a DSA private key using a specified session
//
// Either or both label and/or id can be nil, in which case random values will be generated.
func GenerateDSAKeyPairOnSession(session *PKCS11Session, slot uint, id []byte, label []byte, params *dsa.Parameters) (*PKCS11PrivateKeyDSA, error) {
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
	p := params.P.Bytes()
	q := params.Q.Bytes()
	g := params.G.Bytes()
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_DSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIME, p),
		pkcs11.NewAttribute(pkcs11.CKA_SUBPRIME, q),
		pkcs11.NewAttribute(pkcs11.CKA_BASE, g),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_DSA_KEY_PAIR_GEN, nil)}
	pubHandle, privHandle, err := session.Ctx.GenerateKeyPair(session.Handle,
		mech,
		publicKeyTemplate,
		privateKeyTemplate)
	if err != nil {
		return nil, err
	}
	if pub, err = exportDSAPublicKey(session, pubHandle); err != nil {
		return nil, err
	}
	priv := PKCS11PrivateKeyDSA{PKCS11PrivateKey{PKCS11Object{privHandle, slot}, pub}}
	return &priv, nil
}

// Sign signs a message using a DSA key.
//
// This completes the implemention of crypto.Signer for PKCS11PrivateKeyDSA.
//
// PKCS#11 expects to pick its own random data for signatures, so the rand argument is ignored.
//
// The return value is a DER-encoded byteblock.
func (signer *PKCS11PrivateKeyDSA) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return dsaGeneric(signer.Slot, signer.Handle, pkcs11.CKM_DSA, digest)
}
