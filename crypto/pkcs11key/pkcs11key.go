// +build !nopkcs11

// Package pkcs11key implements crypto.Signer for PKCS #11 private
// keys. Currently, only RSA keys are support.
package pkcs11key

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"io"
	"math/big"

	"github.com/miekg/pkcs11"
)

// from src/pkg/crypto/rsa/pkcs1v15.go
var hashPrefixes = map[crypto.Hash][]byte{
	crypto.MD5:       {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10},
	crypto.SHA1:      {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224:    {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256:    {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384:    {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512:    {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
	crypto.MD5SHA1:   {}, // A special TLS case which doesn't use an ASN1 prefix.
	crypto.RIPEMD160: {0x30, 0x20, 0x30, 0x08, 0x06, 0x06, 0x28, 0xcf, 0x06, 0x03, 0x00, 0x31, 0x04, 0x14},
}

// PKCS11Key is an implementation of the crypto.Signer interface
// using a key stored in a PKCS#11 hardware token.  This enables
// the use of PKCS#11 tokens with the Go x509 library's methods
// for signing certificates.
type PKCS11Key struct {
	// The PKCS#11 library to use
	module *pkcs11.Ctx

	// The PIN to be used to log in to the device
	pin string

	// The name of the slot to be used, or "" to use any slot
	slotDescription string

	// The label of the token to be used, or "" to use any token
	tokenLabel string

	// The label of the private key to be used.
	privateKeyLabel string

	// The public key corresponding to the private key.
	publicKey rsa.PublicKey
}

// New instantiates a new handle to a PKCS #11-backed key.
// The slotDescription and tokenLabel parameters are optional (i.e., if
// they are set to "", they will be ignored).  However, at least one of
// them must be set.
func New(module, slotDescription, tokenLabel, pin, privLabel string) (ps *PKCS11Key, err error) {
	if slotDescription == "" && tokenLabel == "" {
		err = errors.New("either slotDescription or tokenLabel must be specified")
		return
	}

	// Set up a new pkcs11 object and initialize it
	p := pkcs11.New(module)
	if p == nil {
		err = errors.New("unable to load PKCS#11 module")
		return
	}

	if err = p.Initialize(); err != nil {
		return
	}

	// Initialize a partial key
	ps = &PKCS11Key{
		module:          p,
		pin:             pin,
		slotDescription: slotDescription,
		tokenLabel:      tokenLabel,
		privateKeyLabel: privLabel,
	}

	// Populate the pubic key from the private key
	// TODO: Add support for non-RSA keys, switching on CKA_KEY_TYPE
	session, keyHandle, err := ps.openSession()
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	}
	attr, err := p.GetAttributeValue(session, keyHandle, template)
	if err != nil {
		ps.Destroy()
		return
	}
	ps.closeSession(session)

	n := big.NewInt(0)
	e := int(0)
	gotModulus, gotExponent := false, false
	for _, a := range attr {
		if a.Type == pkcs11.CKA_MODULUS {
			n.SetBytes(a.Value)
			gotModulus = true
		} else if a.Type == pkcs11.CKA_PUBLIC_EXPONENT {
			bigE := big.NewInt(0)
			bigE.SetBytes(a.Value)
			e = int(bigE.Int64())
			gotExponent = true
		}
	}
	if !gotModulus || !gotExponent {
		ps.Destroy()
		return
	}
	ps.publicKey = rsa.PublicKey{
		N: n,
		E: e,
	}

	return
}

// Destroy tears down a PKCS11Key.
//
// This method must be called before the PKCS11Key is GC'ed, in order
// to ensure that the PKCS#11 module itself is properly finalized and
// destroyed.
//
// The idiomatic way to do this (assuming no need for a long-lived
// signer) is as follows:
//
//   ps, err := NewPKCS11Signer(...)
//   if err != nil { ... }
//   defer ps.Destroy()
func (ps *PKCS11Key) Destroy() {
	if ps.module != nil {
		ps.module.Finalize()
		ps.module.Destroy()
	}
}

// Look up the token that contains the desired private key
func (ps *PKCS11Key) openSession() (pkcs11.SessionHandle, pkcs11.ObjectHandle, error) {
	var emptySession pkcs11.SessionHandle
	var emptyHandle pkcs11.ObjectHandle

	// Find slot by description
	slots, err := ps.module.GetSlotList(true)
	if err != nil {
		return emptySession, emptyHandle, err
	}
	for _, slot := range slots {
		// If ps.slotDescription is provided, only check matching slots
		if ps.slotDescription != "" {
			slotInfo, err := ps.module.GetSlotInfo(slot)
			if err != nil {
				return emptySession, emptyHandle, err
			}
			if slotInfo.SlotDescription != ps.slotDescription {
				continue
			}
		}

		// If ps.tokenLabel is provided, only check matching slots
		if ps.tokenLabel != "" {
			tokenInfo, err := ps.module.GetTokenInfo(slot)
			if err != nil {
				return emptySession, emptyHandle, err
			}
			if tokenInfo.Label != ps.tokenLabel {
				continue
			}
		}

		// Open session
		session, err := ps.module.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
		if err != nil {
			return emptySession, emptyHandle, err
		}

		// Login
		if err = ps.module.Login(session, pkcs11.CKU_USER, ps.pin); err != nil {
			ps.closeSession(session)
			continue
		}

		// See if the private key is present
		template := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, ps.privateKeyLabel),
		}
		if err = ps.module.FindObjectsInit(session, template); err != nil {
			ps.closeSession(session)
			return emptySession, emptyHandle, err
		}
		objs, _, err := ps.module.FindObjects(session, 2)
		if err != nil {
			ps.closeSession(session)
			return emptySession, emptyHandle, err
		}
		if err = ps.module.FindObjectsFinal(session); err != nil {
			ps.closeSession(session)
			return emptySession, emptyHandle, err
		}

		if len(objs) > 0 {
			return session, objs[0], nil
		}
	}

	return emptySession, emptyHandle, errors.New("slot not found")
}

func (ps *PKCS11Key) closeSession(session pkcs11.SessionHandle) {
	ps.module.Logout(session)
	ps.module.CloseSession(session)
}

// Public returns the public key for the PKCS #11 key.
func (ps *PKCS11Key) Public() crypto.PublicKey {
	return &ps.publicKey
}

// Sign performs a signature using the PKCS #11 key.
func (ps *PKCS11Key) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	// Verify that the length of the hash is as expected
	hash := opts.HashFunc()
	hashLen := hash.Size()
	if len(msg) != hashLen {
		err = errors.New("input size does not match hash function output size")
		return
	}

	// Add DigestInfo prefix
	// TODO: Switch mechanisms based on CKA_KEY_TYPE
	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}
	prefix, ok := hashPrefixes[hash]
	if !ok {
		err = errors.New("unknown hash function")
		return
	}
	signatureInput := append(prefix, msg...)

	// Open a session
	session, keyHandle, err := ps.openSession()
	if err != nil {
		return
	}
	defer ps.closeSession(session)

	// Perform the sign operation
	err = ps.module.SignInit(session, mechanism, keyHandle)
	if err != nil {
		return
	}

	signature, err = ps.module.Sign(session, signatureInput)
	return
}
