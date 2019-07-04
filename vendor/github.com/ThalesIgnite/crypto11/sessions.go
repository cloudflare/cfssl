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
	"context"
	"errors"
	"fmt"
	"github.com/miekg/pkcs11"
	"github.com/youtube/vitess/go/pools"
	"log"
	"sync"
)

// PKCS11Session is a pair of PKCS#11 context and a reference to a loaded session handle.
type PKCS11Session struct {
	Ctx    *pkcs11.Ctx
	Handle pkcs11.SessionHandle
}

// sessionPool is a thread safe pool of PKCS#11 sessions
type sessionPool struct {
	m    sync.RWMutex
	pool map[uint]*pools.ResourcePool
}

// Map of slot IDs to session pools
var pool = newSessionPool()

// Error specifies an event when the requested slot is already set in the sessions pool
var errSlotBusy = errors.New("pool slot busy")

// Error when there is no pool at specific slot in the sessions pool
var errPoolNotFound = errors.New("pool not found")

// Create a new session for a given slot
func newSession(ctx *pkcs11.Ctx, slot uint) (*PKCS11Session, error) {
	session, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, err
	}
	return &PKCS11Session{ctx, session}, nil
}

// Create a new session pool with default configuration
func newSessionPool() *sessionPool {
	return &sessionPool{
		pool: map[uint]*pools.ResourcePool{},
	}
}

// Close closes the session.
//
// Deprecated: Use CloseSession, which returns any underlying errors.
func (session *PKCS11Session) Close() {
	// TODO - when next making breaking changes, kill this method (or fix it)

	// Assign error to "_", to indicate we are knowingly ignoring it
	_ = session.Ctx.CloseSession(session.Handle)
}

// CloseSession closes the session.
func (session *PKCS11Session) CloseSession() error {
	return session.Ctx.CloseSession(session.Handle)
}

// Get returns requested resource pool by slot id
func (p *sessionPool) Get(slot uint) *pools.ResourcePool {
	p.m.RLock()
	defer p.m.RUnlock()
	return p.pool[slot]
}

// Put stores new resource pool into the pool if the requested slot is free
func (p *sessionPool) PutIfAbsent(slot uint, pool *pools.ResourcePool) error {
	p.m.Lock()
	defer p.m.Unlock()
	if _, ok := p.pool[slot]; ok {
		return errSlotBusy
	}
	p.pool[slot] = pool
	return nil
}

// Run a function with a session
//
// setupSessions must have been called for the slot already, otherwise
// an error will be returned.
func withSession(slot uint, f func(session *PKCS11Session) error) error {
	sessionPool := pool.Get(slot)
	if sessionPool == nil {
		return fmt.Errorf("crypto11: no session for slot %d", slot)
	}

	ctx := context.Background()
	if instance.cfg.PoolWaitTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), instance.cfg.PoolWaitTimeout)
		defer cancel()
	}

	session, err := sessionPool.Get(ctx)
	if err != nil {
		return err
	}
	defer sessionPool.Put(session)

	s := session.(*PKCS11Session)
	err = f(s)
	if err != nil {
		// if a request required login, then try to login
		if perr, ok := err.(pkcs11.Error); ok && perr == pkcs11.CKR_USER_NOT_LOGGED_IN && instance.cfg.Pin != "" {
			if err = s.Ctx.Login(s.Handle, pkcs11.CKU_USER, instance.cfg.Pin); err != nil {
				return err
			}
			// retry after login
			return f(s)
		}

		return err
	}

	return nil
}

// Ensures that sessions are setup.
func ensureSessions(ctx *libCtx, slot uint) error {
	if err := setupSessions(ctx, slot); err != nil && err != errSlotBusy {
		return err
	}
	return nil
}

// Create the session pool for a given slot if it does not exist
// already.
func setupSessions(c *libCtx, slot uint) error {
	return pool.PutIfAbsent(slot, pools.NewResourcePool(
		func() (pools.Resource, error) {
			s, err := newSession(c.ctx, slot)
			if err != nil {
				return nil, err
			}

			if instance.token.Flags&pkcs11.CKF_LOGIN_REQUIRED != 0 && instance.cfg.Pin != "" {
				// login required if a pool evict idle sessions or
				// for the first connection in the pool (handled in lib conf)
				if instance.cfg.IdleTimeout > 0 {
					if err = loginToken(s); err != nil {
						return nil, err
					}
				}
			}

			return s, nil
		},
		c.cfg.MaxSessions,
		c.cfg.MaxSessions,
		c.cfg.IdleTimeout,
	))
}

func loginToken(s *PKCS11Session) error {
	// login is pkcs11 context wide, not just handle/session scoped
	err := s.Ctx.Login(s.Handle, pkcs11.CKU_USER, instance.cfg.Pin)
	if err != nil {
		if code, ok := err.(pkcs11.Error); ok && code == pkcs11.CKR_USER_ALREADY_LOGGED_IN {
			return nil
		}
		log.Printf("Failed to open PKCS#11 Session: %s", err.Error())

		closeErr := s.CloseSession()
		if closeErr != nil {
			log.Printf("Failed to close session: %s", closeErr.Error())
		}

		// Return the first error we encountered
		return err
	}
	return nil
}

// Releases a sessions specific to the requested slot if present.
func (p *sessionPool) closeSessions(slot uint) error {
	p.m.Lock()
	defer p.m.Unlock()

	rp, ok := p.pool[slot]
	if !ok {
		return errPoolNotFound
	}

	rp.Close()
	delete(p.pool, slot)

	return nil
}
