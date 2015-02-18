package ubiquity

// This is for cross-platform ubiquity. Basically, here we deal with issues about whether a cert chain
// is acceptable for different platforms, including desktop and mobile ones., and about how to compare
// two chains under the context of cross-platform ubiquity.

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path"
	"path/filepath"
	"time"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
)

// SHA1RawPublicKey returns a SHA1 hash of the raw certificate public key
func SHA1RawPublicKey(cert *x509.Certificate) string {
	return fmt.Sprintf("%x", sha1.Sum(cert.RawSubjectPublicKeyInfo))
}

// CertSet is a succint set of x509 certificates which only stores certificates' SHA1 hashes.
type CertSet map[string]bool

// Lookup returns whether a certificate is stored in the set.
func (s CertSet) Lookup(cert *x509.Certificate) bool {
	return s[SHA1RawPublicKey(cert)]
}

// Add adds a certificate to the set.
func (s CertSet) Add(cert *x509.Certificate) {
	s[SHA1RawPublicKey(cert)] = true
}

// CryptoDeprecationPolicy encodes how a platform plans to deprecate the support of a crypto hash/key algorithm.
type CryptoDeprecationPolicy struct {
	// The name of target algorithm to be deprecated.
	Target string `json:"target"`
	// The date when the policy is effective.
	EffectiveDate time.Time `json:"effective_date"`
	// The expiry deadline indicates the latest date which a end-entity certificate with the deprecating
	// algorithm can be valid through.
	ExpiryDeadline time.Time `json:"expiry_deadline"`
}

// A Platform contains ubiquity information on supported crypto algorithms and root certificate store name.
type Platform struct {
	Name            string                   `json:"name"`
	Weight          int                      `json:"weight"`
	HashAlgo        string                   `json:"hash_algo"`
	KeyAlgo         string                   `json:"key_algo"`
	KeyStoreFile    string                   `json:"keystore"`
	HashDeprecation *CryptoDeprecationPolicy `json:"hash_algo_expiry"`
	KeyStore        CertSet
	HashUbiquity    HashUbiquity
	KeyAlgoUbiquity KeyAlgoUbiquity
}

// Deprecate returns whether the platform rejects the cert chain due to ceased support of a crypto hash algorithm.
func (p Platform) Deprecate(chain []*x509.Certificate) bool {
	if p.HashDeprecation == nil {
		return false
	}
	now := time.Now()
	leaf := chain[0]

	// Currently we implement the logic that Chrome browsers use to stop supporting SHA-1. To our understanding,
	// Microsoft and Mozilla use basically the same logic to cease support of SHA-1 as well.

	if now.After(p.HashDeprecation.EffectiveDate) {
		if leaf.NotAfter.After(p.HashDeprecation.ExpiryDeadline) {
			// Check hash algorithm of non-root cert.
			for i, cert := range chain {
				if i < len(chain)-1 {
					if helpers.HashAlgoString(cert.SignatureAlgorithm) == p.HashDeprecation.Target {
						return true
					}
				}
			}
		}
	}

	return false
}

// Trust returns whether the platform has the root cert in the trusted store.
func (p Platform) Trust(root *x509.Certificate) bool {
	// the key store is empty iff the platform doesn't carry a root store and trust whatever root store
	// is supplied. An example is Chrome. Such platforms should not show up in the untrusted platform
	// list. So always return true here. Also this won't hurt ubiquity scoring because such platforms give
	// no differentiation on root cert selection.
	if len(p.KeyStore) == 0 {
		return true
	}

	return p.KeyStore.Lookup(root)
}

func (p Platform) hashUbiquity() HashUbiquity {
	switch p.HashAlgo {
	case "SHA1":
		return SHA1Ubiquity
	case "SHA2":
		return SHA2Ubiquity
	default:
		return UnknownHashUbiquity
	}
}

func (p Platform) keyAlgoUbiquity() KeyAlgoUbiquity {
	switch p.KeyAlgo {
	case "RSA":
		return RSAUbiquity
	case "ECDSA256":
		return ECDSA256Ubiquity
	case "ECDSA384":
		return ECDSA384Ubiquity
	case "ECDSA521":
		return ECDSA521Ubiquity
	default:
		return UnknownAlgoUbiquity
	}
}

// ParseAndLoad converts HashAlgo and KeyAlgo to corresponding ubiquity value and load
// certificates into internal KeyStore from KeyStoreFiles
func (p *Platform) ParseAndLoad() (ok bool) {
	p.HashUbiquity = p.hashUbiquity()
	p.KeyAlgoUbiquity = p.keyAlgoUbiquity()
	p.KeyStore = map[string]bool{}
	if p.KeyStoreFile != "" {
		pemBytes, err := ioutil.ReadFile(p.KeyStoreFile)
		if err != nil {
			log.Error(err)
			return false
		}
		// Best effort parsing the PEMs such that ignore all borken pem,
		// since some of CA certs have negative serial number which trigger errors.
		for len(pemBytes) > 0 {
			var cert *x509.Certificate
			cert, rest, err := helpers.ParseOneCertificateFromPEM(pemBytes)
			// If one cert is parsed, record the raw SHA1 hash.
			if err == nil && cert != nil {
				p.KeyStore.Add(cert)
			}

			if len(rest) < len(pemBytes) {
				pemBytes = rest
			} else {
				// No progress in bytes parsing, bail out.
				break
			}
		}
	}
	if p.HashUbiquity <= UnknownHashUbiquity ||
		p.KeyAlgoUbiquity <= UnknownAlgoUbiquity {
		return false
	}
	return true
}

// Platforms is the list of platforms against which ubiquity bundling will be optimized.
var Platforms []Platform

// LoadPlatforms reads the file content as a json object array and convert it
// to Platforms.
func LoadPlatforms(filename string) error {
	relativePath := filepath.Dir(filename)
	// Attempt to load root certificate metadata
	log.Debug("Loading platform metadata: ", filename)
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("platform metadata failed to load: %v", err)
	}
	var rawPlatforms []Platform
	if bytes != nil {
		err = json.Unmarshal(bytes, &rawPlatforms)
		if err != nil {
			return fmt.Errorf("platform metadata failed to parse: %v", err)
		}
	}

	for _, platform := range rawPlatforms {
		if platform.KeyStoreFile != "" {
			platform.KeyStoreFile = path.Join(relativePath, platform.KeyStoreFile)
		}
		ok := platform.ParseAndLoad()
		if !ok {
			// erase all loaded platforms
			Platforms = nil
			return fmt.Errorf("fail to finalize the parsing of platform metadata: %v", platform)
		}

		log.Infof("Platform metadata is loaded: %v %v", platform.Name, len(platform.KeyStore))
		Platforms = append(Platforms, platform)
	}

	return nil
}

// UntrustedPlatforms returns a list of platforms which don't trust the root certificate.
func UntrustedPlatforms(root *x509.Certificate) []string {
	ret := []string{}
	for _, platform := range Platforms {
		if !platform.Trust(root) {
			ret = append(ret, platform.Name)
		}
	}
	return ret
}

// DeprecatedSHA1Platforms returns a list of platforms which rejects the cert chain based on deprecation of SHA1.
func DeprecatedSHA1Platforms(chain []*x509.Certificate) []string {
	ret := []string{}
	for _, platform := range Platforms {
		if platform.Deprecate(chain) && platform.HashDeprecation.Target == "SHA1" {
			ret = append(ret, platform.Name)
		}
	}
	return ret
}

// CrossPlatformUbiquity returns a ubiquity score (persumably relecting the market share in percentage)
// based on whether the given chain can be verified with the different platforms' root certificate stores.
func CrossPlatformUbiquity(chain []*x509.Certificate) int {
	// There is no root store info, every chain is equal weighted as 0.
	if len(Platforms) == 0 {
		return 0
	}

	totalWeight := 0
	// A chain is viable with the platform if
	//	1. the root is in the platform's root store
	//	2. the chain satisfy the minimal constraints on hash function and key algorithm.
	root := chain[len(chain)-1]
	for _, platform := range Platforms {
		if platform.Trust(root) && !platform.Deprecate(chain) {
			switch {
			case platform.HashUbiquity <= ChainHashUbiquity(chain) && platform.KeyAlgoUbiquity <= ChainKeyAlgoUbiquity(chain):
				totalWeight += platform.Weight
			}
		}
	}
	return totalWeight
}

// ComparePlatformUbiquity compares the cross-platform ubiquity between chain1 and chain2.
func ComparePlatformUbiquity(chain1, chain2 []*x509.Certificate) int {
	w1 := CrossPlatformUbiquity(chain1)
	w2 := CrossPlatformUbiquity(chain2)
	return w1 - w2
}

// SHA2Homogeneity returns 1 if the chain contains only SHA-2 certs (excluding root). Otherwise it returns 0.
func SHA2Homogeneity(chain []*x509.Certificate) int {
	for i := 0; i < len(chain)-1; i++ {
		if hashUbiquity(chain[i]) != SHA2Ubiquity {
			return 0
		}
	}
	return 1
}

// CompareSHA2Homogeneity compares the chains based on SHA2 homogeneity. Full SHA-2 chain (excluding root) is rated higher that the rest.
func CompareSHA2Homogeneity(chain1, chain2 []*x509.Certificate) int {
	w1 := SHA2Homogeneity(chain1)
	w2 := SHA2Homogeneity(chain2)
	return w1 - w2
}
