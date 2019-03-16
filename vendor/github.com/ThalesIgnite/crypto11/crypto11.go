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

// Package crypto11 enables access to cryptographic keys from PKCS#11 using Go crypto API.
//
// Simple use
//
// 1. Either write a configuration file (see ConfigureFromFile) or
// define a configuration in your application (see PKCS11Config and
// Configure). This will identify the PKCS#11 library and token to
// use, and contain the password (or "PIN" in PKCS#11 terminology) to
// use if the token requires login.
//
// 2. Create keys with GenerateDSAKeyPair, GenerateRSAKeyPair and
// GenerateECDSAKeyPair. The keys you get back implement the standard
// Go crypto.Signer interface (and crypto.Decrypter, for RSA). They
// are automatically persisted under random a randomly generated label
// and ID (use the Identify method to discover them).
//
// 3. Retrieve existing keys with FindKeyPair. The return value is a
// Go crypto.PrivateKey; it may be converted either to crypto.Signer
// or to *PKCS11PrivateKeyDSA, *PKCS11PrivateKeyECDSA or
// *PKCS11PrivateKeyRSA.
//
// Sessions and concurrency
//
// Note that PKCS#11 session handles must not be used concurrently
// from multiple threads. Consumers of the Signer interface know
// nothing of this and expect to be able to sign from multiple threads
// without constraint. We address this as follows.
//
// 1. PKCS11Object captures both the object handle and the slot ID
// for an object.
//
// 2. For each slot we maintain a pool of read-write sessions. The
// pool expands dynamically up to an (undocumented) limit.
//
// 3. Each operation transiently takes a session from the pool. They
// have exclusive use of the session, meeting PKCS#11's concurrency
// requirements.
//
// The details are, partially, exposed in the API; since the target
// use case is PKCS#11-unaware operation it may be that the API as it
// stands isn't good enough for PKCS#11-aware applications. Feedback
// welcome.
//
// See also https://golang.org/pkg/crypto/
//
// Limitations
//
// The PKCS1v15DecryptOptions SessionKeyLen field is not implemented
// and an error is returned if it is nonzero.
// The reason for this is that it is not possible for crypto11 to guarantee the constant-time behavior in the specification.
// See https://github.com/thalesignite/crypto11/issues/5 for further discussion.
//
// Symmetric crypto support via cipher.Block is very slow.
// You can use the BlockModeCloser API
// but you must call the Close() interface (not found in cipher.BlockMode).
// See https://github.com/ThalesIgnite/crypto11/issues/6 for further discussion.
package crypto11

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/miekg/pkcs11"
)

const (
	// DefaultMaxSessions controls the maximum number of concurrent sessions to
	// open, unless otherwise specified in the PKCS11Config object.
	DefaultMaxSessions = 1024
)

// ErrTokenNotFound represents the failure to find the requested PKCS#11 token
var ErrTokenNotFound = errors.New("crypto11: could not find PKCS#11 token")

// ErrKeyNotFound represents the failure to find the requested PKCS#11 key
var ErrKeyNotFound = errors.New("crypto11: could not find PKCS#11 key")

// ErrNotConfigured is returned when the PKCS#11 library is not configured
var ErrNotConfigured = errors.New("crypto11: PKCS#11 not yet configured")

// ErrCannotOpenPKCS11 is returned when the PKCS#11 library cannot be opened
var ErrCannotOpenPKCS11 = errors.New("crypto11: could not open PKCS#11")

// ErrCannotGetRandomData is returned when the PKCS#11 library fails to return enough random data
var ErrCannotGetRandomData = errors.New("crypto11: cannot get random data from PKCS#11")

// ErrUnsupportedKeyType is returned when the PKCS#11 library returns a key type that isn't supported
var ErrUnsupportedKeyType = errors.New("crypto11: unrecognized key type")

// PKCS11Object contains a reference to a loaded PKCS#11 object.
type PKCS11Object struct {
	// The PKCS#11 object handle.
	Handle pkcs11.ObjectHandle

	// The PKCS#11 slot number.
	//
	// This is used internally to find a session handle that can
	// access this object.
	Slot uint
}

// PKCS11PrivateKey contains a reference to a loaded PKCS#11 private key object.
type PKCS11PrivateKey struct {
	PKCS11Object

	// The corresponding public key
	PubKey crypto.PublicKey
}

// In a former design we carried around the object handle for the
// public key and retrieved it on demand.  The downside of that is
// that the Public() method on Signer &c has no way to communicate
// errors.

/* Nasty globals */
var instance = &libCtx{
	cfg: &PKCS11Config{
		MaxSessions:     DefaultMaxSessions,
		IdleTimeout:     0,
		PoolWaitTimeout: 0,
	},
}

// Represent library pkcs11 context and token configuration
type libCtx struct {
	ctx *pkcs11.Ctx
	cfg *PKCS11Config

	token *pkcs11.TokenInfo
	slot  uint
}

// Find a token given its serial number
func findToken(slots []uint, serial string, label string) (uint, *pkcs11.TokenInfo, error) {
	for _, slot := range slots {
		tokenInfo, err := instance.ctx.GetTokenInfo(slot)
		if err != nil {
			return 0, nil, err
		}
		if tokenInfo.SerialNumber == serial {
			return slot, &tokenInfo, nil
		}
		if tokenInfo.Label == label {
			return slot, &tokenInfo, nil
		}
	}
	return 0, nil, ErrTokenNotFound
}

// PKCS11Config holds PKCS#11 configuration information.
//
// A token may be identified either by serial number or label.  If
// both are specified then the first match wins.
//
// Supply this to Configure(), or alternatively use ConfigureFromFile().
type PKCS11Config struct {
	// Full path to PKCS#11 library
	Path string

	// Token serial number
	TokenSerial string

	// Token label
	TokenLabel string

	// User PIN (password)
	Pin string

	// Maximum number of concurrent sessions to open
	MaxSessions int

	// Session idle timeout to be evicted from the pool
	IdleTimeout time.Duration

	// Maximum time allowed to wait a sessions pool for a session
	PoolWaitTimeout time.Duration
}

// Configure configures PKCS#11 from a PKCS11Config.
//
// The PKCS#11 library context is returned,
// allowing a PKCS#11-aware application to make use of it. Non-aware
// appliations may ignore it.
//
// Unsually, these values may be present even if the error is
// non-nil. This corresponds to the case that the library has already
// been configured. Note that it is NOT reconfigured so if you supply
// a different configuration the second time, it will be ignored in
// favor of the first configuration.
//
// If config is nil, and the library has already been configured, the
// context from the first configuration is returned (and
// the error will be nil in this case).
func Configure(config *PKCS11Config) (*pkcs11.Ctx, error) {
	var err error
	var slots []uint

	if config == nil {
		if instance.ctx != nil {
			return instance.ctx, nil
		}
		return nil, ErrNotConfigured
	}
	if instance.ctx != nil {
		log.Printf("PKCS#11 library already configured")
		return instance.ctx, nil
	}

	if config.MaxSessions == 0 {
		config.MaxSessions = DefaultMaxSessions
	}
	instance.cfg = config
	instance.ctx = pkcs11.New(config.Path)
	if instance.ctx == nil {
		log.Printf("Could not open PKCS#11 library: %s", config.Path)
		return nil, ErrCannotOpenPKCS11
	}
	if err = instance.ctx.Initialize(); err != nil {
		log.Printf("Failed to initialize PKCS#11 library: %s", err.Error())
		return nil, err
	}
	if slots, err = instance.ctx.GetSlotList(true); err != nil {
		log.Printf("Failed to list PKCS#11 Slots: %s", err.Error())
		return nil, err
	}

	instance.slot, instance.token, err = findToken(slots, config.TokenSerial, config.TokenLabel)
	if err != nil {
		log.Printf("Failed to find Token in any Slot: %s", err.Error())
		return nil, err
	}

	if instance.token.MaxRwSessionCount > 0 && uint(instance.cfg.MaxSessions) > instance.token.MaxRwSessionCount {
		return nil, fmt.Errorf("crypto11: provided max sessions value (%d) exceeds max value the token supports (%d)", instance.cfg.MaxSessions, instance.token.MaxRwSessionCount)
	}

	if err := setupSessions(instance, instance.slot); err != nil {
		return nil, err
	}

	// login required if a pool evict idle sessions (handled by the pool) or
	// for the first connection in the pool (handled here)
	if instance.cfg.IdleTimeout == 0 {
		if instance.token.Flags&pkcs11.CKF_LOGIN_REQUIRED != 0 && instance.cfg.Pin != "" {
			if err = withSession(instance.slot, loginToken); err != nil {
				return nil, err
			}
		}
	}

	return instance.ctx, nil
}

// ConfigureFromFile configures PKCS#11 from a name configuration file.
//
// Configuration files are a JSON representation of the PKCSConfig object.
// The return value is as for Configure().
//
// Note that if CRYPTO11_CONFIG_PATH is set in the environment,
// configuration will be read from that file, overriding any later
// runtime configuration.
func ConfigureFromFile(configLocation string) (ctx *pkcs11.Ctx, err error) {
	file, err := os.Open(configLocation)
	if err != nil {
		log.Printf("Could not open config file: %s", configLocation)
		return nil, err
	}
	defer func() {
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
	}()

	configDecoder := json.NewDecoder(file)
	config := &PKCS11Config{}
	err = configDecoder.Decode(config)
	if err != nil {
		log.Printf("Could decode config file: %s", err.Error())
		return nil, err
	}
	return Configure(config)
}

// Close releases all sessions and uninitializes library default handle.
// Once library handle is released, library may be configured once again.
func Close() error {
	ctx := instance.ctx
	if ctx != nil {
		slots, err := ctx.GetSlotList(true)
		if err != nil {
			return err
		}

		for _, slot := range slots {
			if err := pool.closeSessions(slot); err != nil && err != errPoolNotFound {
				return err
			}
			// if something by passed cache
			if err := ctx.CloseAllSessions(slot); err != nil {
				return err
			}
		}

		if err := ctx.Finalize(); err != nil {
			return err
		}

		ctx.Destroy()
		instance.ctx = nil
	}

	return nil
}

func init() {
	if configLocation, ok := os.LookupEnv("CRYPTO11_CONFIG_PATH"); ok {
		if _, err := ConfigureFromFile(configLocation); err != nil {
			panic(err)
		}
	}
}
