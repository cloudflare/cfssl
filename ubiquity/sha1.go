package ubiquity

import (
	"crypto/x509"
	"time"

	"github.com/cloudflare/cfssl/helpers"
)

// SHA1Deprecated encodes how a platform deprecates the support of SHA1
type SHA1Deprecated struct {
	Name string `json:"name"`
	// The date when the policy is effective. zero value means effective immediately
	EffectiveDate time.Time `json:"effective_date"`
	// The expiry deadline indicates the latest date which a end-entity
	// certificate with SHA1 can be valid through.
	ExpiryDeadline time.Time `json:"expiry_deadline"`
	// The date beyond which SHA1 cert should not be issued.
	NeverIssueAfter time.Time `json:"never_issue_after"`
}

// SHA1Deprecateds is the list of platforms which deprecate the use of SHA1
var SHA1Deprecateds = []SHA1Deprecated{
	// Chrome:
	//   if the leaf certificate expires after Jan. 1st 2016
	//   and the chain (excluding root) contains SHA-1 cert, reject it.
	SHA1Deprecated{
		Name:           "Google Chrome 42 and later",
		ExpiryDeadline: time.Date(2016, time.January, 1, 0, 0, 0, 0, time.UTC),
	},
	// Mozilla Firefox developer console:
	//   if the leaf certificate expires after Jan. 1st 2017, and
	//   the chain (excluding root) contains SHA-1 cert, show a warning.
	SHA1Deprecated{
		Name:           "Mozilla Firefox 36 (and later) developer console",
		ExpiryDeadline: time.Date(2017, time.January, 1, 0, 0, 0, 0, time.UTC),
	},
	// Mozilla Firefox:
	//   if a new certificate is issued after Jan. 1st 2016, and
	//   it is a SHA-1 cert, reject it.
	SHA1Deprecated{
		Name:            "Mozilla Firefox post-2016 releases",
		EffectiveDate:   time.Date(2016, time.January, 1, 0, 0, 0, 0, time.UTC),
		NeverIssueAfter: time.Date(2016, time.January, 1, 0, 0, 0, 0, time.UTC),
	},
	// Mozilla Firefox:
	//   deprecate all valid SHA-1 cert chain on Jan. 1st 2017
	SHA1Deprecated{
		Name:           "Mozilla Firefox post-2017 releases",
		EffectiveDate:  time.Date(2017, time.January, 1, 0, 0, 0, 0, time.UTC),
		ExpiryDeadline: time.Date(2017, time.January, 1, 0, 0, 0, 0, time.UTC),
	},
	// Microsoft Windows:
	//   deprecate all valid SHA-1 cert chain on Jan. 1st 2017
	SHA1Deprecated{
		Name:           "Microsoft Windows Vista and later",
		EffectiveDate:  time.Date(2017, time.January, 1, 0, 0, 0, 0, time.UTC),
		ExpiryDeadline: time.Date(2017, time.January, 1, 0, 0, 0, 0, time.UTC),
	},
}

// Reject returns whether the platform rejects the cert chain due to ceased
// support of SHA1.
func (p SHA1Deprecated) Reject(chain []*x509.Certificate) bool {
	leaf := chain[0]

	if time.Now().After(p.EffectiveDate) {

		// Reject newly issued leaf certificate with SHA-1 after the specified deadline.
		if !p.NeverIssueAfter.IsZero() && leaf.NotBefore.After(p.NeverIssueAfter) {
			// Check hash algorithm of non-root leaf cert.
			if len(chain) > 1 && helpers.HashAlgoString(leaf.SignatureAlgorithm) == "SHA1" {
				return true
			}
		}

		// Reject certificate chain with SHA-1 that are still valid after expiry deadline.
		if !p.ExpiryDeadline.IsZero() && leaf.NotAfter.After(p.ExpiryDeadline) {
			// Check hash algorithm of non-root certs.
			for i, cert := range chain {
				if i < len(chain)-1 {
					if helpers.HashAlgoString(cert.SignatureAlgorithm) == "SHA1" {
						return true
					}
				}
			}
		}
	}

	return false
}

// DeprecatedSHA1Platforms returns a list of platforms which reject the cert chain based on deprecation of SHA1.
func DeprecatedSHA1Platforms(chain []*x509.Certificate) []string {
	list := []string{}
	for _, platform := range SHA1Deprecateds {
		if platform.Reject(chain) {
			list = append(list, platform.Name)
		}
	}
	return list
}
