package main

import (
	"crypto/x509"

	"github.com/cloudflare/cfssl/bundler"
	"github.com/cloudflare/cfssl/log"
)

type MultirootBundler struct {
	*bundler.Bundler
}

// NewMultirootBundler will set up a bundler with the systems root store
// as caBundle. Intermediate certificates can be added later via AddIntermediate()
func NewMultirootBundler() (*MultirootBundler, error) {
	b, err := bundler.NewBundlerFromPEM(nil, nil)
	if err != nil {
		log.Errorf("failed creating empty bundler")
		return nil, err
	}
	return &MultirootBundler{Bundler: b}, nil
}

func (m *MultirootBundler) AddRoot(cert *x509.Certificate) {
	// Initialize a RootPool then the first root cert is added
	// If none is added, systems root store will be used
	if m.Bundler.RootPool == nil {
		m.Bundler.RootPool = x509.NewCertPool()
	}
	m.Bundler.RootPool.AddCert(cert)
	m.Bundler.KnownIssuers[string(cert.Signature)] = true
}

func (m *MultirootBundler) AddIntermediate(cert *x509.Certificate) {
	m.Bundler.IntermediatePool.AddCert(cert)
	m.Bundler.KnownIssuers[string(cert.Signature)] = true
}
