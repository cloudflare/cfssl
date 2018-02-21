// Copyright 2016 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fixchain

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/x509"
)

// Limiter is an interface to allow different rate limiters to be used with the
// Logger.
type Limiter interface {
	Wait()
}

// Logger contains methods to asynchronously log certificate chains to a
// Certificate Transparency log and properties to store information about each
// attempt that is made to post a certificate chain to said log.
type Logger struct {
	ctx    context.Context
	client client.AddLogClient
	roots  *x509.CertPool
	toPost chan *toPost
	errors chan<- *FixError

	active uint32

	queued        uint32 // How many chains have been queued to be posted.
	posted        uint32 // How many chains have been posted.
	reposted      uint32 // How many chains for an already-posted cert have been queued.
	chainReposted uint32 // How many chains have been queued again.

	// Note that wg counts the number of active requests, not
	// active servers, because we can't close it to signal the
	// end, because of retries.
	wg      sync.WaitGroup
	limiter Limiter

	postCertCache  *lockedMap
	postChainCache *lockedMap
}

// IsPosted tells the caller whether a chain for the given certificate has
// already been successfully posted to the log by this Logger.
func (l *Logger) IsPosted(cert *x509.Certificate) bool {
	return l.postCertCache.get(hash(cert))
}

// QueueChain adds the given chain to the queue to be posted to the log.
func (l *Logger) QueueChain(chain []*x509.Certificate) {
	if chain == nil {
		return
	}

	atomic.AddUint32(&l.queued, 1)
	// Has a chain for the cert this chain if for already been successfully
	//posted to the log by this Logger?
	h := hash(chain[0]) // Chains are cert -> root
	if l.postCertCache.get(h) {
		atomic.AddUint32(&l.reposted, 1)
		return // Don't post chain for a cert that has already had a chain posted.
	}
	// If we assume all chains for the same cert are equally
	// likely to succeed, then we could mark the cert as posted
	// here. However, bugs might cause a log to refuse one chain
	// and accept another, so try each unique chain.

	// Has this Logger already tried to post this chain?
	h = hashChain(chain)
	if l.postChainCache.get(h) {
		atomic.AddUint32(&l.chainReposted, 1)
		return
	}
	l.postChainCache.set(h, true)

	l.postToLog(&toPost{chain: chain})
}

// Wait for all of the active requests to finish being processed.
func (l *Logger) Wait() {
	l.wg.Wait()
}

// RootCerts returns the root certificates that the log accepts.
func (l *Logger) RootCerts() *x509.CertPool {
	if l.roots == nil {
		// Retry if unable to get roots.
		for i := 0; i < 10; i++ {
			roots, err := l.getRoots()
			if err == nil {
				l.roots = roots
				return l.roots
			}
			log.Println(err)
		}
		log.Fatalf("Can't get roots for log")
	}
	return l.roots
}

func (l *Logger) getRoots() (*x509.CertPool, error) {
	roots, err := l.client.GetAcceptedRoots(l.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get roots: %s", err)
	}
	ret := x509.NewCertPool()
	for _, root := range roots {
		r, err := x509.ParseCertificate(root.Data)
		switch err.(type) {
		case nil, x509.NonFatalErrors:
			// ignore
		default:
			return nil, fmt.Errorf("can't parse certificate: %s %#v", err, root.Data)
		}
		ret.AddCert(r)
	}
	return ret, nil
}

type toPost struct {
	chain []*x509.Certificate
}

// postToLog(), rather than its asynchronous couterpart asyncPostToLog(), is
// used during the initial queueing of chains to avoid spinning up an excessive
// number of goroutines, and unecessarily using up memory. If asyncPostToLog()
// was called instead, then every time a new chain was queued, a new goroutine
// would be created, each holding their own chain - regardless of whether there
// were postServers available to process them or not.  If a large number of
// chains were queued in a short period of time, this could lead to a large
// number of these additional goroutines being created, resulting in excessive
// memory usage.
func (l *Logger) postToLog(p *toPost) {
	l.wg.Add(1) // Add to the wg as we are adding a new active request to the logger queue.
	l.toPost <- p
}

// asyncPostToLog(), rather than its synchronous couterpart postToLog(), is used
// during retries to avoid deadlock. Without the separate goroutine created in
// asyncPostToLog(), deadlock can occur in the following situation:
//
// Suppose there is only one postServer() goroutine running, and it is blocked
// waiting for a toPost on the toPost chan.  A toPost gets added to the chan,
// which causes the following to happen:
// - the postServer takes the toPost from the chan.
// - the postServer calls l.postChain(toPost), and waits for
//   l.postChain() to return before going back to the toPost
//   chan for another toPost.
// - l.postChain() begins execution.  Suppose the first post
//   attempt of the toPost fails for some network-related
//   reason.
// - l.postChain retries and calls l.postToLog() to queue up the
//   toPost to try to post it again.
// - l.postToLog() tries to put the toPost on the toPost chan,
//   and blocks until a postServer takes it off the chan.
// But the one and only postServer is still waiting for l.postChain (and
// therefore l.postToLog) to return, and will not go to take another toPost off
// the toPost chan until that happens.
// Thus, deadlock.
//
// Similar situations with multiple postServers can easily be imagined.
func (l *Logger) asyncPostToLog(p *toPost) {
	l.wg.Add(1) // Add to the wg as we are adding a new active request to the logger queue.
	go func() {
		l.toPost <- p
	}()
}

func (l *Logger) postChain(p *toPost) {
	h := hash(p.chain[0])
	if l.postCertCache.get(h) {
		atomic.AddUint32(&l.reposted, 1)
		return
	}

	derChain := make([]ct.ASN1Cert, 0, len(p.chain))
	for _, cert := range p.chain {
		derChain = append(derChain, ct.ASN1Cert{Data: cert.Raw})
	}

	l.limiter.Wait()
	atomic.AddUint32(&l.posted, 1)
	_, err := l.client.AddChain(l.ctx, derChain)
	if err != nil {
		l.errors <- &FixError{
			Type:  LogPostFailed,
			Chain: p.chain,
			Error: fmt.Errorf("add-chain failed: %s", err),
		}
		return
	}

	// If the post was successful, cache.
	l.postCertCache.set(h, true)
}

func (l *Logger) postServer() {
	for {
		c := <-l.toPost
		atomic.AddUint32(&l.active, 1)
		l.postChain(c)
		atomic.AddUint32(&l.active, ^uint32(0))
		l.wg.Done()
	}
}

func (l *Logger) logStats() {
	t := time.NewTicker(time.Second)
	go func() {
		for range t.C {
			log.Printf("posters: %d active, %d posted, %d queued, %d certs requeued, %d chains requeued",
				l.active, l.posted, l.queued, l.reposted, l.chainReposted)
		}
	}()
}

// NewLogger creates a new asynchronous logger to log chains to the
// Certificate Transparency log at the given url.  It starts up a pool of
// workerCount workers.  Errors are pushed to the errors channel.  client is
// used to post the chains to the log.
func NewLogger(ctx context.Context, workerCount int, errors chan<- *FixError, client client.AddLogClient, limiter Limiter, logStats bool) *Logger {
	l := &Logger{
		ctx:            ctx,
		client:         client,
		errors:         errors,
		toPost:         make(chan *toPost),
		postCertCache:  newLockedMap(),
		postChainCache: newLockedMap(),
		limiter:        limiter,
	}
	l.RootCerts()

	// Start post server pool.
	for i := 0; i < workerCount; i++ {
		go l.postServer()
	}

	if logStats {
		l.logStats()
	}
	return l
}
