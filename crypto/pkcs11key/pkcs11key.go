// +build !nopkcs11

// Package pkcs11key implements crypto.Signer for PKCS #11 private
// keys. Currently, only RSA keys are supported.
// See ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-11/v2-30/pkcs-11v2-30b-d6.pdf for
// details of the Cryptoki PKCS#11 API.
package pkcs11key

import (
	"crypto"
	"crypto/rsa"
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

// PKCS11Key is an implementation of the crypto.Signer interface
// using a key stored in a PKCS#11 hardware token.  This enables
// the use of PKCS#11 tokens with the Go x509 library's methods
// for signing certificates.
//
// Each PKCS11Key represents one session. Its session handle is
// protected internally by a mutex, so at most one Sign operation can be active
// at a time. For best performance you may want to instantiate multiple PKCS11Keys.
// Each one will have its own session and can be used concurrently. Note that
// some smartcards like the Yubikey Neo do not support multiple simultaneous
// sessions and will error out on creation of the second PKCS11Key object.
//
// Note: For parallel usage, it is *highly* recommended that you create all your
// PKCS11Key objects serially, on your main thread, checking for errors each
// time, and then farm them out for use by different goroutines. If you fail to
// do this, your application may attempt to login repeatedly with an incorrect
// PIN, locking the PKCS#11 token.
type PKCS11Key struct {
	// The PKCS#11 library to use
	module *pkcs11.Ctx

	// The path to the PKCS#11 library
	modulePath string

	// The name of the slot to be used, or "" to use any slot
	slotDescription string

	// The label of the token to be used (mandatory).
	// We will automatically search for this in the slot list.
	tokenLabel string

	// The PIN to be used to log in to the device
	pin string

	// The public key corresponding to the private key.
	publicKey rsa.PublicKey

	// The an ObjectHandle pointing to the private key on the HSM.
	privateKeyHandle pkcs11.ObjectHandle

	// A handle to the session used by this PKCS11Key.
	session *pkcs11.SessionHandle
	sessionMu sync.Mutex
}

var modules = make(map[string]*pkcs11.Ctx);
var modulesMu sync.Mutex;

// initialize loads the given PKCS#11 module (shared library) if it is not
// already loaded. It's an error to load a PKCS#11 module multiple times, so we
// maintain a map of loaded modules. Note that there is no facility yet to
// unload a module ("finalize" in PKCS#11 parlance). In general, modules will
// be unloaded at the end of the process.  The only place where you are likely
// to need to explicitly unload a module is if you fork your process after a
// PKCS11Key has already been created, and the child process also needs to use
// that module.
func initialize(modulePath string) (*pkcs11.Ctx, error) {
	modulesMu.Lock()
	defer modulesMu.Unlock()
	module, ok := modules[modulePath]
	if ok {
		return module, nil
	}

	module = pkcs11.New(modulePath)

	if module == nil {
		return nil, fmt.Errorf("unable to load PKCS#11 module")
	}

	err := module.Initialize()
	if err != nil {
		return nil, err
	}

	modules[modulePath] = module

	return module, nil
}

// New instantiates a new handle to a PKCS #11-backed key.
func New(modulePath, slotDescription, tokenLabel, pin, privateKeyLabel string) (ps *PKCS11Key, err error) {
	module, err := initialize(modulePath)
	if err != nil {
		return
	}
	if module == nil {
		err = fmt.Errorf("nil module")
		return
	}

	// Initialize a partial key
	ps = &PKCS11Key{
		module:          module,
		modulePath:      modulePath,
		slotDescription: slotDescription,
		tokenLabel:      tokenLabel,
		pin:             pin,
	}

	// Open a session
	ps.sessionMu.Lock()
	defer ps.sessionMu.Unlock()
	session, err := ps.openSession()
	if err != nil {
		return
	}
	ps.session = &session

	// Fetch the private key by its label
	privateKeyHandle, err := getPrivateKey(module, session, privateKeyLabel)
	if err != nil {
		ps.module.CloseSession(session)
		return
	}
	ps.privateKeyHandle = privateKeyHandle

	publicKey, err := getPublicKey(module, session, privateKeyHandle)
	if err != nil {
		ps.module.CloseSession(session)
		return
	}
	ps.publicKey = publicKey

	return
}

func getPrivateKey(module *pkcs11.Ctx, session pkcs11.SessionHandle, label string) (pkcs11.ObjectHandle, error) {
	var noHandle pkcs11.ObjectHandle
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	if err := module.FindObjectsInit(session, template); err != nil {
		return noHandle, err
	}
	objs, _, err := module.FindObjects(session, 2)
	if err != nil {
		return noHandle, err
	}
	if err = module.FindObjectsFinal(session); err != nil {
		return noHandle, err
	}

	if len(objs) == 0 {
		return noHandle, fmt.Errorf("private key not found")
	}
	return objs[0], nil
}

// Get the public key matching a private key
// TODO: Add support for non-RSA keys, switching on CKA_KEY_TYPE
func getPublicKey(module *pkcs11.Ctx, session pkcs11.SessionHandle, privateKeyHandle pkcs11.ObjectHandle) (rsa.PublicKey, error) {
	var noKey rsa.PublicKey
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
	if !gotModulus || !gotExponent {
		return noKey, errors.New("public key missing either modulus or exponent")
	}
	return rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}


// Destroy tears down a PKCS11Key by closing the session. It should be
// called before the key gets GC'ed, to avoid leaving dangling sessions.
// NOTE: We do not want to call module.Logout here. module.Logout applies
// application-wide. So if there are multiple sessions active, the other ones
// would be logged out as well, causing CKR_OBJECT_HANDLE_INVALID next
// time they try to sign something. It's also unnecessary to log out explicitly:
// module.CloseSession will log out once the last session in the application is
// closed.
func (ps *PKCS11Key) Destroy() {
	if ps.session != nil {
		ps.sessionMu.Lock()
		ps.module.CloseSession(*ps.session)
		ps.session = nil
		ps.sessionMu.Unlock()
	}
}

func (ps *PKCS11Key) openSession() (pkcs11.SessionHandle, error) {
	var noSession pkcs11.SessionHandle
	slots, err := ps.module.GetSlotList(true)
	if err != nil {
		return noSession, err
	}

	for _, slot := range slots {
		// If ps.slotDescription is provided, only check matching slots
		if ps.slotDescription != "" {
			slotInfo, err := ps.module.GetSlotInfo(slot)
			if err != nil {
				return noSession, err
			}
			if slotInfo.SlotDescription != ps.slotDescription {
				continue
			}
		}

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
			ps.module.CloseSession(session)
			return session, err
		}

		return session, err
	}
	return noSession, fmt.Errorf("No slot found matching token label '%s'", ps.tokenLabel)
}

// Public returns the public key for the PKCS #11 key.
func (ps *PKCS11Key) Public() crypto.PublicKey {
	return &ps.publicKey
}

// Sign performs a signature using the PKCS #11 key.
func (ps *PKCS11Key) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	ps.sessionMu.Lock()
	defer ps.sessionMu.Unlock()
	if ps.session == nil {
		return nil, errors.New("Session was nil")
	}

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

	// Perform the sign operation
	err = ps.module.SignInit(*ps.session, mechanism, ps.privateKeyHandle)
	if err != nil {
		return nil, fmt.Errorf("SignInit problem: %s", err)
	}

	signature, err = ps.module.Sign(*ps.session, signatureInput)
	return
}
