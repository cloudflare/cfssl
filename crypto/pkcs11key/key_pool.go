package pkcs11key

import (
	"sync"
	"io"
	"crypto"
	"fmt"
)

// PKCS11KeyPool is a pool of PKCS11Keys suitable for high performance parallel
// work. PKCS11Key on its own is suitable for multi-threaded use because it has
// built-in locking, but one PKCS11Key can have at most one operation inflight
// at a time. If you are using an HSM that supports multiple sessions, you may
// want to use a PKCS11KeyPool instead, which contains multiple signers.
// PKCS11KeyPool satisfies the Signer interface just as PKCS11Key does, and
// farms out work to multiple sessions under the hood. This assumes you are
// calling Sign from multiple goroutines (as would be common in an RPC or HTTP
// environment). If you only call Sign from a single goroutine, you will only
// ever get single-session performance.
type PKCS11KeyPool struct {
	// This slice acts more or less like a concurrent stack. Keys are popped off
	// the top for use, and then pushed back on when they are no longer in use.
	signers    []*PKCS11Key
	// The initial length of signers, before any are popped off for use.
	totalCount int
	// This variable signals the condition that there are PKCS11Keys available to be
	// used.
	cond    *sync.Cond
}

func (p *PKCS11KeyPool) get() *PKCS11Key {
	p.cond.L.Lock()
	for len(p.signers) == 0 {
		p.cond.Wait()
	}

	instance := p.signers[len(p.signers)-1]
	p.signers = p.signers[:len(p.signers)-1]
	p.cond.L.Unlock()
	return instance
}

func (p *PKCS11KeyPool) put(instance *PKCS11Key) {
	p.cond.L.Lock()
	p.signers = append(p.signers, instance)
	p.cond.Signal()
	p.cond.L.Unlock()
}

// Sign performs a signature using an available PKCS #11 key. If there is no key
// available, it blocks until there is.
func (p *PKCS11KeyPool) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	instance := p.get()
	defer p.put(instance)
	return instance.Sign(rand, msg, opts)
}

func (p *PKCS11KeyPool) Public() crypto.PublicKey {
	instance := p.get()
	defer p.put(instance)
	return instance.Public()
}

// NewPool creates a pool of PKCS11Keys of size n.
func NewPool(n int, modulePath, tokenLabel, pin, privateKeyLabel string) (*PKCS11KeyPool, error) {
	var err error
	signers := make([]*PKCS11Key, n)
	for i := 0; i < n; i++ {
		signers[i], err = New(modulePath, tokenLabel, pin, privateKeyLabel)
		// If any of the signers fail, exit early. This could be, e.g., a bad PIN,
		// and we want to make sure not to lock the token.
		if err != nil {
			for j := 0; j < i; j++ {
				signers[j].Destroy()
			}
			return nil, fmt.Errorf("Problem making PKCS11Key: %s", err)
		}
	}

	var mutex sync.Mutex
	return &PKCS11KeyPool{
		signers: signers,
		totalCount: len(signers),
		cond: sync.NewCond(&mutex),
	}, nil
}

// Destroy calls destroy for each of the member keys, shutting down their
// sessions.
func (p *PKCS11KeyPool) Destroy() {
	for i := 0; i < p.totalCount; i++ {
		p.get().Destroy()
	}
}
