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
	"sync"

	"github.com/google/certificate-transparency-go/x509"
)

type dedupedChain struct {
	certs []*x509.Certificate
}

func (d *dedupedChain) addCert(cert *x509.Certificate) {
	// Check that the certificate isn't being added twice.
	for _, c := range d.certs {
		if c.Equal(cert) {
			return
		}
	}
	d.certs = append(d.certs, cert)
}

func (d *dedupedChain) addCertToFront(cert *x509.Certificate) {
	// Check that the certificate isn't being added twice.
	for _, c := range d.certs {
		if c.Equal(cert) {
			return
		}
	}
	d.certs = append([]*x509.Certificate{cert}, d.certs...)
}

func newDedupedChain(chain []*x509.Certificate) *dedupedChain {
	d := &dedupedChain{}
	for _, cert := range chain {
		d.addCert(cert)
	}
	return d
}

type lockedMap struct {
	m map[[hashSize]byte]bool
	sync.RWMutex
}

func newLockedMap() *lockedMap {
	return &lockedMap{m: make(map[[hashSize]byte]bool)}
}

func (m *lockedMap) get(hash [hashSize]byte) bool {
	m.RLock()
	defer m.RUnlock()
	return m.m[hash]
}

func (m *lockedMap) set(hash [hashSize]byte, b bool) {
	m.Lock()
	defer m.Unlock()
	m.m[hash] = b
}
