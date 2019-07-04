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
	"context"
	"crypto/cipher"
	"fmt"
	"github.com/miekg/pkcs11"
	"github.com/youtube/vitess/go/pools"
	"runtime"
)

// cipher.BlockMode -----------------------------------------------------

// BlockModeCloser represents a block cipher running in a block-based mode (e.g. CBC).
//
// BlockModeCloser embeds cipher.BlockMode, and can be used as such.
// However, in this case
// (or if the Close() method is not explicitly called for any other reason),
// resources allocated to it may remain live indefinitely.
type BlockModeCloser interface {
	cipher.BlockMode

	// Close() releases resources associated with the block mode.
	Close()
}

const (
	modeEncrypt = iota // blockModeCloser is in encrypt mode
	modeDecrypt        // blockModeCloser is in decrypt mode
)

// NewCBCEncrypter returns a cipher.BlockMode which encrypts in cipher block chaining mode, using the given key.
// The length of iv must be the same as the key's block size.
//
// The new BlockMode acquires persistent resources which are released (eventually) by a finalizer.
// If this is a problem for your application then use NewCBCEncrypterCloser instead.
//
// If that is not possible then adding calls to runtime.GC() may help.
func (key *PKCS11SecretKey) NewCBCEncrypter(iv []byte) (bm cipher.BlockMode, err error) {
	return key.newBlockModeCloser(key.Cipher.CBCMech, modeEncrypt, iv, true)
}

// NewCBCDecrypter returns a cipher.BlockMode which decrypts in cipher block chaining mode, using the given key.
// The length of iv must be the same as the key's block size and must match the iv used to encrypt the data.
//
// The new BlockMode acquires persistent resources which are released (eventually) by a finalizer.
// If this is a problem for your application then use NewCBCDecrypterCloser instead.
//
// If that is not possible then adding calls to runtime.GC() may help.
func (key *PKCS11SecretKey) NewCBCDecrypter(iv []byte) (bm cipher.BlockMode, err error) {
	return key.newBlockModeCloser(key.Cipher.CBCMech, modeDecrypt, iv, true)
}

// NewCBCEncrypterCloser returns a  BlockModeCloser which encrypts in cipher block chaining mode, using the given key.
// The length of iv must be the same as the key's block size.
//
// Use of NewCBCEncrypterCloser rather than NewCBCEncrypter represents a commitment to call the Close() method
// of the returned BlockModeCloser.
func (key *PKCS11SecretKey) NewCBCEncrypterCloser(iv []byte) (bmc BlockModeCloser, err error) {
	return key.newBlockModeCloser(key.Cipher.CBCMech, modeEncrypt, iv, false)
}

// NewCBCDecrypterCloser returns a  BlockModeCloser which decrypts in cipher block chaining mode, using the given key.
// The length of iv must be the same as the key's block size and must match the iv used to encrypt the data.
//
// Use of NewCBCDecrypterCloser rather than NewCBCEncrypter represents a commitment to call the Close() method
// of the returned BlockModeCloser.
func (key *PKCS11SecretKey) NewCBCDecrypterCloser(iv []byte) (bmc BlockModeCloser, err error) {
	return key.newBlockModeCloser(key.Cipher.CBCMech, modeDecrypt, iv, false)
}

// blockModeCloser is a concrete implementation of BlockModeCloser supporting CBC.
type blockModeCloser struct {
	// PKCS#11 session to use
	session *PKCS11Session

	// Cipher block size
	blockSize int

	// modeDecrypt or modeEncrypt
	mode int

	// Cleanup function
	cleanup func()
}

// newBlockModeCloser creates a new blockModeCloser for the chosen mechanism and mode.
func (key *PKCS11SecretKey) newBlockModeCloser(mech uint, mode int, iv []byte, setFinalizer bool) (bmc *blockModeCloser, err error) {
	// TODO maybe refactor with withSession()
	sessionPool := pool.Get(key.Slot)
	if sessionPool == nil {
		err = fmt.Errorf("crypto11: no session for slot %d", key.Slot)
		return
	}
	ctx := context.Background()
	if instance.cfg.PoolWaitTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), instance.cfg.PoolWaitTimeout)
		defer cancel()
	}
	var session pools.Resource
	if session, err = sessionPool.Get(ctx); err != nil {
		return
	}
	bmc = &blockModeCloser{
		session:   session.(*PKCS11Session),
		blockSize: key.Cipher.BlockSize,
		mode:      mode,
		cleanup: func() {
			sessionPool.Put(session)
		},
	}
	mechDescription := []*pkcs11.Mechanism{pkcs11.NewMechanism(mech, iv)}
	switch mode {
	case modeDecrypt:
		err = bmc.session.Ctx.DecryptInit(bmc.session.Handle, mechDescription, key.Handle)
	case modeEncrypt:
		err = bmc.session.Ctx.EncryptInit(bmc.session.Handle, mechDescription, key.Handle)
	default:
		panic("unexpected mode")
	}
	if err != nil {
		bmc.cleanup()
		return
	}
	if setFinalizer {
		runtime.SetFinalizer(bmc, finalizeBlockModeCloser)
	}
	return
}

func finalizeBlockModeCloser(obj interface{}) {
	obj.(*blockModeCloser).Close()
}

func (bmc *blockModeCloser) BlockSize() int {
	return bmc.blockSize
}

func (bmc *blockModeCloser) CryptBlocks(dst, src []byte) {
	if len(dst) < len(src) {
		panic("destination buffer too small")
	}
	if len(src)%bmc.blockSize != 0 {
		panic("input is not a whole number of blocks")
	}
	var result []byte
	var err error
	switch bmc.mode {
	case modeDecrypt:
		result, err = bmc.session.Ctx.DecryptUpdate(bmc.session.Handle, src)
	case modeEncrypt:
		result, err = bmc.session.Ctx.EncryptUpdate(bmc.session.Handle, src)
	}
	if err != nil {
		panic(err)
	}
	// PKCS#11 2.40 s5.2 says that the operation must produce as much output
	// as possible, so we should never have less than we submitted for CBC.
	// This could be different for other modes but we don't implement any yet.
	if len(result) != len(src) {
		panic("nontrivial result from *Final operation")
	}
	copy(dst[:len(result)], result)
	runtime.KeepAlive(bmc)
}

func (bmc *blockModeCloser) Close() {
	if bmc.session == nil {
		return
	}
	var result []byte
	var err error
	switch bmc.mode {
	case modeDecrypt:
		result, err = bmc.session.Ctx.DecryptFinal(bmc.session.Handle)
	case modeEncrypt:
		result, err = bmc.session.Ctx.EncryptFinal(bmc.session.Handle)
	}
	bmc.session = nil
	bmc.cleanup()
	if err != nil {
		panic(err)
	}
	// PKCS#11 2.40 s5.2 says that the operation must produce as much output
	// as possible, so we should never have any left over for CBC.
	// This could be different for other modes but we don't implement any yet.
	if len(result) > 0 {
		panic("nontrivial result from *Final operation")
	}
}
