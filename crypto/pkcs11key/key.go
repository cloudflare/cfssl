// +build !nopkcs11

// Package pkcs11key implements crypto.Signer for PKCS #11 private
// keys. Currently, only RSA keys are supported.
// See ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-11/v2-30/pkcs-11v2-30b-d6.pdf for
// details of the Cryptoki PKCS#11 API.
package pkcs11key

import (
	"crypto"
	"crypto/rsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"

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

// from src/pkg/crypto/x509/x509.go
var (
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

func namedCurveFromOID(oid asn1.ObjectIdentifier) elliptic.Curve {
	switch {
	case oid.Equal(oidNamedCurveP224):
		return elliptic.P224()
	case oid.Equal(oidNamedCurveP256):
		return elliptic.P256()
	case oid.Equal(oidNamedCurveP384):
		return elliptic.P384()
	case oid.Equal(oidNamedCurveP521):
		return elliptic.P521()
	}
	return nil
}

// ctx defines the subset of pkcs11.ctx's methods that we use, so we can inject
// a different ctx for testing.
type ctx interface {
	CloseSession(sh pkcs11.SessionHandle) error
	FindObjectsFinal(sh pkcs11.SessionHandle) error
	FindObjectsInit(sh pkcs11.SessionHandle, temp []*pkcs11.Attribute) error
	FindObjects(sh pkcs11.SessionHandle, max int) ([]pkcs11.ObjectHandle, bool, error)
	GetAttributeValue(sh pkcs11.SessionHandle, o pkcs11.ObjectHandle, a []*pkcs11.Attribute) ([]*pkcs11.Attribute, error)
	GetSlotList(tokenPresent bool) ([]uint, error)
	GetTokenInfo(slotID uint) (pkcs11.TokenInfo, error)
	Initialize() error
	Login(sh pkcs11.SessionHandle, userType uint, pin string) error
	Logout(sh pkcs11.SessionHandle) error
	OpenSession(slotID uint, flags uint) (pkcs11.SessionHandle, error)
	SignInit(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism, o pkcs11.ObjectHandle) error
	Sign(sh pkcs11.SessionHandle, message []byte) ([]byte, error)
}

// KeyType is to track the type of the key (based on CKA_KEY_TYPE)
type KeyType int

const (
	// RSA means the key is an RSA key
	RSA KeyType = 0
	// EC means the key is an Elliptic Curve key
	EC  KeyType = 3
)

// Key is an implementation of the crypto.Signer interface using a key stored
// in a PKCS#11 hardware token.  This enables the use of PKCS#11 tokens with
// the Go x509 library's methods for signing certificates.
//
// Each Key represents one session. Its session handle is protected internally
// by a mutex, so at most one Sign operation can be active at a time. For best
// performance you may want to instantiate multiple Keys using pkcs11key.Pool.
// Each one will have its own session and can be used concurrently. Note that
// some smartcards like the Yubikey Neo do not support multiple simultaneous
// sessions and will error out on creation of the second Key object.
//
// Note: If you instantiate multiple Keys without using Pool, it is *highly*
// recommended that you create all your Key objects serially, on your main
// thread, checking for errors each time, and then farm them out for use by
// different goroutines. If you fail to do this, your application may attempt
// to login repeatedly with an incorrect PIN, locking the PKCS#11 token.
type Key struct {
	// The PKCS#11 library to use
	module ctx

	// The label of the token to be used (mandatory).
	// We will automatically search for this in the slot list.
	tokenLabel string

	// The PIN to be used to log in to the device
	pin string

	// The public key corresponding to the private key.
	rsaPublicKey rsa.PublicKey
	ecdsaPublicKey ecdsa.PublicKey

	// The an ObjectHandle pointing to the private key on the HSM.
	privateKeyHandle pkcs11.ObjectHandle

	// The key type (RSA or EC)
	keyType KeyType

	// A handle to the session used by this Key.
	session   *pkcs11.SessionHandle
	sessionMu sync.Mutex

	// True if the private key has the CKA_ALWAYS_AUTHENTICATE attribute set.
	alwaysAuthenticate bool
}

var modules = make(map[string]ctx)
var modulesMu sync.Mutex

// initialize loads the given PKCS#11 module (shared library) if it is not
// already loaded. It's an error to load a PKCS#11 module multiple times, so we
// maintain a map of loaded modules. Note that there is no facility yet to
// unload a module ("finalize" in PKCS#11 parlance). In general, modules will
// be unloaded at the end of the process.  The only place where you are likely
// to need to explicitly unload a module is if you fork your process after a
// Key has already been created, and the child process also needs to use
// that module.
func initialize(modulePath string) (ctx, error) {
	modulesMu.Lock()
	defer modulesMu.Unlock()
	module, ok := modules[modulePath]
	if ok {
		return module, nil
	}

	newModule := ctx(pkcs11.New(modulePath))

	if newModule == nil {
		return nil, fmt.Errorf("unable to load PKCS#11 module")
	}

	err := newModule.Initialize()
	if err != nil {
		return nil, err
	}

	modules[modulePath] = newModule

	return newModule, nil
}

// New instantiates a new handle to a PKCS #11-backed key.
func New(modulePath, tokenLabel, pin, privateKeyLabel string) (ps *Key, err error) {
	module, err := initialize(modulePath)
	if err != nil {
		return
	}
	if module == nil {
		err = fmt.Errorf("nil module")
		return
	}

	// Initialize a partial key
	ps = &Key{
		module:     module,
		tokenLabel: tokenLabel,
		pin:        pin,
	}
	err = ps.setup(privateKeyLabel)
	if err != nil {
		return
	}
	return ps, nil
}

func (ps *Key) setup(privateKeyLabel string) (err error) {
	// Open a session
	ps.sessionMu.Lock()
	defer ps.sessionMu.Unlock()
	session, err := ps.openSession()
	if err != nil {
		return
	}
	ps.session = &session

	// Fetch the private key by its label
	privateKeyHandle, err := ps.getPrivateKey(ps.module, session, privateKeyLabel)
	if err != nil {
		ps.module.CloseSession(session)
		return
	}
	ps.privateKeyHandle = privateKeyHandle

	publicKey, err := ps.getPublicKey(ps.module, session, privateKeyHandle)
	if err != nil {
		ps.module.CloseSession(session)
		return
	}
	if(ps.keyType == EC) {
		ps.ecdsaPublicKey = publicKey.(ecdsa.PublicKey)
	} else {
		ps.rsaPublicKey = publicKey.(rsa.PublicKey)
	}

	return
}

func (ps *Key) getPrivateKey(module ctx, session pkcs11.SessionHandle, label string) (pkcs11.ObjectHandle, error) {
	var noHandle pkcs11.ObjectHandle
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	if err := module.FindObjectsInit(session, template); err != nil {
		return noHandle, err
	}
	objs, _, err := module.FindObjects(session, 1)
	if err != nil {
		return noHandle, err
	}
	if err = module.FindObjectsFinal(session); err != nil {
		return noHandle, err
	}

	if len(objs) == 0 {
		return noHandle, fmt.Errorf("private key not found")
	}
	privateKeyHandle := objs[0]

	attributes, err := module.GetAttributeValue(session, privateKeyHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, false),
	})
	if err != nil {
		return noHandle, err
	}
	for i, attribute := range attributes {
		if i == 0 && len(attribute.Value) > 0 {
			if attribute.Value[0] == pkcs11.CKK_RSA {
				ps.keyType = RSA
			} else if attribute.Value[0] == pkcs11.CKK_EC {
				ps.keyType = EC
			} else {
				return noHandle, fmt.Errorf("Unsupported key type %d", attribute.Value)
			}
		}
	}

	// Check whether the key has the CKA_ALWAYS_AUTHENTICATE attribute.
	// If so, fail: we don't want to have to re-authenticate for each sign
	// operation.
	attributes, err = module.GetAttributeValue(session, privateKeyHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ALWAYS_AUTHENTICATE, false),
	})
	// The PKCS#11 spec states that C_GetAttributeValue may return
	// CKR_ATTRIBUTE_TYPE_INVALID if an object simply does not posses a given
	// attribute. We don't consider that an error: the absence of the
	// CKR_ATTRIBUTE_TYPE_INVALID property is just fine.
	if err != nil && err == pkcs11.Error(pkcs11.CKR_ATTRIBUTE_TYPE_INVALID) {
		return privateKeyHandle, nil
	} else if err != nil {
		return noHandle, err
	}
	for _, attribute := range attributes {
		if len(attribute.Value) > 0 && attribute.Value[0] == 1 {
			ps.alwaysAuthenticate = true
		}
	}

	return privateKeyHandle, nil
}

// Get the public key matching an RSA private key
func getRSAPublicKey(module ctx, session pkcs11.SessionHandle, privateKeyHandle pkcs11.ObjectHandle) (interface{}, error) {
	var noKey interface{}
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	}
	attr, err := module.GetAttributeValue(session, privateKeyHandle, template)
	if err != nil {
		return noKey, err
	}

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
	if !gotModulus {
		return noKey, errors.New("private key missing modulus")
	}
	if !gotExponent {
		return noKey, errors.New("private key missing exponent")
	}

	rsa := rsa.PublicKey{
		N: n,
		E: e,
	}
	return rsa, nil
}

// Get the public key matching an Elliptic Curve private key
func getECPublicKey(module ctx, session pkcs11.SessionHandle, privateKeyHandle pkcs11.ObjectHandle) (interface{}, error) {
	var noKey interface{}

	// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/os/pkcs11-curr-v2.40-os.html#_Toc416960012
	template := []*pkcs11.Attribute{
		// CKA_EC_PARAMS contains the OID of the curve (part of the
		// public key
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
		// CKA_ID will allow use to find the corresponding public key
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
	}

	attr, err := module.GetAttributeValue(session, privateKeyHandle, template)
	if err != nil {
		return noKey, err
	}

	oid := []byte {}
	id := []byte {}
	gotOid, gotID := false, false
	for _, a := range attr {
		if a.Type == pkcs11.CKA_EC_PARAMS {
			oid = a.Value
			gotOid = true
		} else if a.Type == pkcs11.CKA_ID {
			id = a.Value
			gotID = true
		}
	}
	if !gotOid {
		return noKey, errors.New("private key missing curve parameters")
	}
	if !gotID {
		return noKey, errors.New("private key missing identifier (CKA_ID)")
	}

	poid := new(asn1.ObjectIdentifier)
	asn1.Unmarshal(oid, poid)
	curve := namedCurveFromOID(*poid)

	templateSearch := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}

	if err := module.FindObjectsInit(session, templateSearch); err != nil {
		return noKey, err
	}
	objs, _, err := module.FindObjects(session, 1)
	if err != nil {
		return noKey, err
	}
	if err = module.FindObjectsFinal(session); err != nil {
		return noKey, err
	}

	if len(objs) == 0 {
		return noKey, fmt.Errorf("public key not found")
	}
	publicKeyHandle := objs[0]

	templatePub := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	}

	attrPub, err := module.GetAttributeValue(session, publicKeyHandle, templatePub)
	if err != nil {
		return noKey, err
	}

	ecPoint := []byte{}
	gotEcPoint := false
	for _, a := range attrPub {
		if a.Type == pkcs11.CKA_EC_POINT {
			ecPoint = a.Value
			gotEcPoint = true
		}
	}
	if !gotEcPoint {
		return noKey, errors.New("public key missing EC Point")
	}

	x, y := readECPoint(curve, ecPoint)
	ecdsa := ecdsa.PublicKey{
		Curve: curve,
		X: x,
		Y: y,
	}
	return ecdsa, nil
}

// Decode Q point from CKA_EC_POINT attribute
func readECPoint(curve elliptic.Curve, ecpoint []byte) (*big.Int, *big.Int) {
	x, y := elliptic.Unmarshal(curve, ecpoint)
	if x == nil {
		// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/os/pkcs11-curr-v2.40-os.html#_ftn1
		// PKCS#11 v2.20 specified that the CKA_EC_POINT was to be store in a DER-encoded
		// OCTET STRING.
		var point asn1.RawValue
		asn1.Unmarshal(ecpoint, &point)
		x, y = elliptic.Unmarshal(curve, point.Bytes)
	}
	return x, y
}

// Get the public key matching a private key
func (ps *Key) getPublicKey(module ctx, session pkcs11.SessionHandle, privateKeyHandle pkcs11.ObjectHandle) (interface{}, error) {
	var noKey interface{}
	if ps.keyType == RSA {
		return getRSAPublicKey(module, session, privateKeyHandle)
	} else if ps.keyType == EC {
		return getECPublicKey(module, session, privateKeyHandle)
	}
	return noKey, fmt.Errorf("invalid key type")
}

// Destroy tears down a Key by closing the session. It should be
// called before the key gets GC'ed, to avoid leaving dangling sessions.
func (ps *Key) Destroy() error {
	if ps.session != nil {
		// NOTE: We do not want to call module.Logout here. module.Logout applies
		// application-wide. So if there are multiple sessions active, the other ones
		// would be logged out as well, causing CKR_OBJECT_HANDLE_INVALID next
		// time they try to sign something. It's also unnecessary to log out explicitly:
		// module.CloseSession will log out once the last session in the application is
		// closed.
		ps.sessionMu.Lock()
		defer ps.sessionMu.Unlock()
		err := ps.module.CloseSession(*ps.session)
		ps.session = nil
		if err != nil {
			return err
		}
	}
	return nil
}

func (ps *Key) openSession() (pkcs11.SessionHandle, error) {
	var noSession pkcs11.SessionHandle
	slots, err := ps.module.GetSlotList(true)
	if err != nil {
		return noSession, err
	}

	for _, slot := range slots {
		// Check that token label matches.
		tokenInfo, err := ps.module.GetTokenInfo(slot)
		if err != nil {
			return noSession, err
		}
		if tokenInfo.Label != ps.tokenLabel {
			continue
		}

		// Open session
		session, err := ps.module.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
		if err != nil {
			return session, err
		}

		// Login
		// Note: Logged-in status is application-wide, not per session. But in
		// practice it appears to be okay to login to a token multiple times with the same
		// credentials.
		if err = ps.module.Login(session, pkcs11.CKU_USER, ps.pin); err != nil {
			if err == pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
				// But if the token says we're already logged in, it's ok.
				err = nil
			} else {
				ps.module.CloseSession(session)
				return session, err
			}
		}

		return session, err
	}
	return noSession, fmt.Errorf("No slot found matching token label '%s'", ps.tokenLabel)
}

// Public returns the public key for the PKCS #11 key.
func (ps *Key) Public() crypto.PublicKey {
	if(ps.keyType == EC) {
		return &ps.ecdsaPublicKey
	}
	return &ps.rsaPublicKey
}

// Sign performs a signature using the PKCS #11 key.
func (ps *Key) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	ps.sessionMu.Lock()
	defer ps.sessionMu.Unlock()
	if ps.session == nil {
		return nil, errors.New("Session was nil")
	}

	// When the alwaysAuthenticate bit is true (e.g. on a Yubikey NEO in PIV mode),
	// each Sign has to include a Logout/Login, or the next Sign request will get
	// CKR_USER_NOT_LOGGED_IN. This is very slow, but on the NEO it's not possible
	// to clear the CKA_ALWAYS_AUTHENTICATE bit, so this is the only available
	// workaround.
	// Also, since logged in / logged out is application state rather than session
	// state, we take a global lock while we do the logout and login, and during
	// the signing.
	if ps.alwaysAuthenticate {
		modulesMu.Lock()
		defer modulesMu.Unlock()
		if err := ps.module.Logout(*ps.session); err != nil {
			return nil, fmt.Errorf("logout: %s", err)
		}
		if err = ps.module.Login(*ps.session, pkcs11.CKU_USER, ps.pin); err != nil {
			return nil, fmt.Errorf("login: %s", err)
		}
	}

	// Verify that the length of the hash is as expected
	hash := opts.HashFunc()
	hashLen := hash.Size()
	if len(msg) != hashLen {
		err = fmt.Errorf("input size does not match hash function output size: %d vs %d", len(msg), hashLen)
		return
	}

	// Add DigestInfo prefix
	var mechanism []*pkcs11.Mechanism
	var signatureInput []byte

	if ps.keyType == RSA {
		mechanism = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}
		prefix, ok := hashPrefixes[hash]
		if !ok {
			err = errors.New("unknown hash function")
			return
		}
		signatureInput = append(prefix, msg...)
	} else if ps.keyType == EC {
		mechanism = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}
		signatureInput = msg
	}

	// Perform the sign operation
	err = ps.module.SignInit(*ps.session, mechanism, ps.privateKeyHandle)
	if err != nil {
		return nil, fmt.Errorf("sign init: %s", err)
	}

	signature, err = ps.module.Sign(*ps.session, signatureInput)
	if err != nil {
		return nil, fmt.Errorf("sign: %s", err)
	}
	return
}
