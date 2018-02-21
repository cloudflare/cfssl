// Copyright 2014 Google Inc. All Rights Reserved.
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

package scanner

import (
	"context"
	"log"
	"math/big"
	"regexp"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/x509"
)

// Matcher describes how to match certificates and precertificates, based solely on the parsed [pre-]certificate;
// clients should implement this interface to perform their own match criteria.
type Matcher interface {
	// CertificateMatches is called by the scanner for each X509 Certificate found in the log.
	// The implementation should return true if the passed Certificate is interesting, and false otherwise.
	CertificateMatches(*x509.Certificate) bool

	// PrecertificateMatches is called by the scanner for each CT Precertificate found in the log.
	// The implementation should return true if the passed Precertificate is interesting, and false otherwise.
	PrecertificateMatches(*ct.Precertificate) bool
}

// MatchAll is a Matcher which will match every possible Certificate and Precertificate.
type MatchAll struct{}

// CertificateMatches returns true if the given cert should match; in this case, always.
func (m MatchAll) CertificateMatches(_ *x509.Certificate) bool {
	return true
}

// PrecertificateMatches returns true if the given precert should match, in this case, always.
func (m MatchAll) PrecertificateMatches(_ *ct.Precertificate) bool {
	return true
}

// MatchNone is a Matcher which will never match any Certificate or Precertificate.
type MatchNone struct{}

// CertificateMatches returns true if the given cert should match; in this case, never.
func (m MatchNone) CertificateMatches(_ *x509.Certificate) bool {
	return false
}

// PrecertificateMatches returns true if the given cert should match; in this case, never.
func (m MatchNone) PrecertificateMatches(_ *ct.Precertificate) bool {
	return false
}

// MatchSerialNumber performs a match for a specific serial number.
type MatchSerialNumber struct {
	SerialNumber big.Int
}

// CertificateMatches returns true if the given cert should match; in this
// case, only if the serial number matches.
func (m MatchSerialNumber) CertificateMatches(c *x509.Certificate) bool {
	return c.SerialNumber.String() == m.SerialNumber.String()
}

// PrecertificateMatches returns true if the given cert should match; in this
// case, only if the serial number matches.
func (m MatchSerialNumber) PrecertificateMatches(p *ct.Precertificate) bool {
	return p.TBSCertificate.SerialNumber.String() == m.SerialNumber.String()
}

// MatchSubjectRegex is a Matcher which will use CertificateSubjectRegex and PrecertificateSubjectRegex
// to determine whether Certificates and Precertificates are interesting.
// The two regexes are tested against Subject CN (Common Name) as well as all
// Subject Alternative Names
type MatchSubjectRegex struct {
	CertificateSubjectRegex    *regexp.Regexp
	PrecertificateSubjectRegex *regexp.Regexp
}

// CertificateMatches returns true if either CN or any SAN of c matches m.CertificateSubjectRegex.
func (m MatchSubjectRegex) CertificateMatches(c *x509.Certificate) bool {
	if m.CertificateSubjectRegex.FindStringIndex(c.Subject.CommonName) != nil {
		return true
	}
	for _, alt := range c.DNSNames {
		if m.CertificateSubjectRegex.FindStringIndex(alt) != nil {
			return true
		}
	}
	return false
}

// PrecertificateMatches returns true if either CN or any SAN of p matches m.PrecertificateSubjectRegex.
func (m MatchSubjectRegex) PrecertificateMatches(p *ct.Precertificate) bool {
	if m.PrecertificateSubjectRegex.FindStringIndex(p.TBSCertificate.Subject.CommonName) != nil {
		return true
	}
	for _, alt := range p.TBSCertificate.DNSNames {
		if m.PrecertificateSubjectRegex.FindStringIndex(alt) != nil {
			return true
		}
	}
	return false
}

// MatchIssuerRegex matches on issuer CN (common name) by regex
type MatchIssuerRegex struct {
	CertificateIssuerRegex    *regexp.Regexp
	PrecertificateIssuerRegex *regexp.Regexp
}

// CertificateMatches returns true if the given cert's CN matches.
func (m MatchIssuerRegex) CertificateMatches(c *x509.Certificate) bool {
	return m.CertificateIssuerRegex.FindStringIndex(c.Issuer.CommonName) != nil
}

// PrecertificateMatches returns true if the given precert's CN matches.
func (m MatchIssuerRegex) PrecertificateMatches(p *ct.Precertificate) bool {
	return m.PrecertificateIssuerRegex.FindStringIndex(p.TBSCertificate.Issuer.CommonName) != nil
}

// LeafMatcher describes how to match log entries, based on the Log LeafEntry
// (which includes the unparsed [pre-]certificate; clients should implement this
// interface to perform their own match criteria.
type LeafMatcher interface {
	Matches(*ct.LeafEntry) bool
}

// CertParseFailMatcher is a LeafMatcher which will match any Certificate or Precertificate that
// triggered an error on parsing.
type CertParseFailMatcher struct {
	MatchNonFatalErrs bool
}

// Matches returns true for parse errors.
func (m CertParseFailMatcher) Matches(leaf *ct.LeafEntry) bool {
	_, err := ct.LogEntryFromLeaf(1, leaf)
	if err != nil {
		if _, ok := err.(x509.NonFatalErrors); ok {
			return m.MatchNonFatalErrs
		}
		return true
	}
	return false
}

// CertVerifyFailMatcher is a LeafMatcher which will match any Certificate or Precertificate that fails
// validation.  The PopulateRoots() method should be called before use.
type CertVerifyFailMatcher struct {
	roots *x509.CertPool
}

// PopulateRoots adds the accepted roots for the log to the pool for validation.
func (m *CertVerifyFailMatcher) PopulateRoots(ctx context.Context, logClient *client.LogClient) {
	if m.roots != nil {
		return
	}
	m.roots = x509.NewCertPool()
	roots, err := logClient.GetAcceptedRoots(ctx)
	if err != nil {
		log.Fatal(err)
	}
	for _, root := range roots {
		cert, _ := x509.ParseCertificate(root.Data)
		if cert != nil {
			m.roots.AddCert(cert)
		} else {
			log.Fatal(err)
		}
	}
}

// Matches returns true for validation errors.
func (m CertVerifyFailMatcher) Matches(leaf *ct.LeafEntry) bool {
	entry, _ := ct.LogEntryFromLeaf(1, leaf)
	if entry == nil {
		// Can't validate if we can't parse
		return false
	}
	// Validate the [pre-]certificate as of just before its expiry.
	var notBefore time.Time
	if entry.X509Cert != nil {
		notBefore = entry.X509Cert.NotAfter
	} else {
		notBefore = entry.Precert.TBSCertificate.NotAfter
	}
	when := notBefore.Add(-1 * time.Second)
	opts := x509.VerifyOptions{
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		Roots:         m.roots,
		Intermediates: x509.NewCertPool(),
		CurrentTime:   when,
	}
	for ii, cert := range entry.Chain {
		intermediate, err := x509.ParseCertificate(cert.Data)
		if intermediate == nil {
			log.Printf("Intermediate %d fails to parse: %v", ii, err)
			return true
		}
		opts.Intermediates.AddCert(intermediate)
	}
	if entry.X509Cert != nil {
		_, err := entry.X509Cert.Verify(opts)
		if err != nil {
			log.Printf("Cert fails to validate as of %v: %v", opts.CurrentTime, err)
			return true
		}
		return false
	}
	// TODO(drysdale) add precert validation
	return false
}
