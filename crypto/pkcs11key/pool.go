// +build !nopkcs11

package pkcs11key

import (
	"crypto"
	"fmt"
	"io"
	"sync"
)

// Pool is a pool of Keys suitable for high performance parallel work. Key
// on its own is suitable for multi-threaded use because it has built-in
// locking, but one Key can have at most one operation inflight at a time.
// If you are using an HSM that supports multiple sessions, you may want to
// use a Pool instead, which contains multiple signers. Pool satisfies the
// Signer interface just as Key does, and farms out work to multiple sessions
// under the hood. This assumes you are calling Sign from multiple goroutines
// (as would be common in an RPC or HTTP environment). If you only call Sign
// from a single goroutine, you will only ever get single-session performance.
type Pool struct {
	// This slice acts more or less like a concurrent stack. Keys are popped off
	// the top for use, and then pushed back on when they are no longer in use.
	signers []*Key
	// The initial length of signers, before any are popped off for use.
	totalCount int
	// This variable signals the condition that there are Keys available to be
	// used.
	cond *sync.Cond
}

func (p *Pool) get() *Key {
	p.cond.L.Lock()
	for len(p.signers) == 0 {
		p.cond.Wait()
	}

	instance := p.signers[len(p.signers)-1]
	p.signers = p.signers[:len(p.signers)-1]
	p.cond.L.Unlock()
	return instance
}

func (p *Pool) put(instance *Key) {
	p.cond.L.Lock()
	p.signers = append(p.signers, instance)
	p.cond.Signal()
	p.cond.L.Unlock()
}

// Sign performs a signature using an available PKCS #11 key. If there is no key
// available, it blocks until there is.
func (p *Pool) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	instance := p.get()
	defer p.put(instance)
	return instance.Sign(rand, msg, opts)
}

// Public returns the public key of any one of the signers in the pool. Since
// they were all created with the same arguments, the public key should be the
// same for each one.
func (p *Pool) Public() crypto.PublicKey {
	instance := p.get()
	defer p.put(instance)
	return instance.Public()
}

// NewPool creates a pool of Keys of size n.
func NewPool(n int, modulePath, tokenLabel, pin, privateKeyLabel string) (*Pool, error) {
	var err error
	signers := make([]*Key, n)
	for i := 0; i < n; i++ {
		signers[i], err = New(modulePath, tokenLabel, pin, privateKeyLabel)
		// If any of the signers fail, exit early. This could be, e.g., a bad PIN,
		// and we want to make sure not to lock the token.
		if err != nil {
			for j := 0; j < i; j++ {
				signers[j].Destroy()
			}
			return nil, fmt.Errorf("pkcs11key: problem making Key: %s", err)
		}
	}

	var mutex sync.Mutex
	return &Pool{
		signers:    signers,
		totalCount: len(signers),
		cond:       sync.NewCond(&mutex),
	}, nil
}

// Destroy calls destroy for each of the member keys, shutting down their
// sessions.
func (p *Pool) Destroy() error {
	for i := 0; i < p.totalCount; i++ {
		err := p.get().Destroy()
		if err != nil {
			return fmt.Errorf("destroy error: %s", err)
		}
	}
	return nil
}
