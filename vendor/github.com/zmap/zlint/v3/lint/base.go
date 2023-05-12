package lint

/*
 * ZLint Copyright 2021 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

import (
	"fmt"
	"time"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/util"
)

// LintInterface is implemented by each Lint.
type LintInterface interface { //nolint:revive
	// CheckApplies runs once per certificate. It returns true if the Lint should
	// run on the given certificate. If CheckApplies returns false, the Lint
	// result is automatically set to NA without calling CheckEffective() or
	// Run().
	CheckApplies(c *x509.Certificate) bool

	// Execute() is the body of the lint. It is called for every certificate for
	// which CheckApplies() returns true.
	Execute(c *x509.Certificate) *LintResult
}

// Configurable lints return a pointer into a struct that they wish to receive their configuration into.
type Configurable interface {
	Configure() interface{}
}

// A Lint struct represents a single lint, e.g.
// "e_basic_constraints_not_critical". It contains an implementation of LintInterface.
type Lint struct {

	// Name is a lowercase underscore-separated string describing what a given
	// Lint checks. If Name beings with "w", the lint MUST NOT return Error, only
	// Warn. If Name beings with "e", the Lint MUST NOT return Warn, only Error.
	Name string `json:"name,omitempty"`

	// A human-readable description of what the Lint checks. Usually copied
	// directly from the CA/B Baseline Requirements or RFC 5280.
	Description string `json:"description,omitempty"`

	// The source of the check, e.g. "BRs: 6.1.6" or "RFC 5280: 4.1.2.6".
	Citation string `json:"citation,omitempty"`

	// Programmatic source of the check, BRs, RFC5280, or ZLint
	Source LintSource `json:"source"`

	// Lints automatically returns NE for all certificates where CheckApplies() is
	// true but with NotBefore < EffectiveDate. This check is bypassed if
	// EffectiveDate is zero. Please see CheckEffective for more information.
	EffectiveDate time.Time `json:"-"`

	// Lints automatically returns NE for all certificates where CheckApplies() is
	// true but with NotBefore >= IneffectiveDate. This check is bypassed if
	// IneffectiveDate is zero. Please see CheckEffective for more information.
	IneffectiveDate time.Time `json:"-"`

	// A constructor which returns the implementation of the lint logic.
	Lint func() LintInterface `json:"-"`
}

// CheckEffective returns true if c was issued on or after the EffectiveDate
// AND before (but not on) the Ineffective date. That is, CheckEffective
// returns true if...
//
// 	c.NotBefore in [EffectiveDate, IneffectiveDate)
//
// If EffectiveDate is zero, then only IneffectiveDate is checked. Conversely,
// if IneffectiveDate is zero then only EffectiveDate is checked. If both EffectiveDate
// and IneffectiveDate are zero then CheckEffective always returns true.
func (l *Lint) CheckEffective(c *x509.Certificate) bool {
	onOrAfterEffective := l.EffectiveDate.IsZero() || util.OnOrAfter(c.NotBefore, l.EffectiveDate)
	strictlyBeforeIneffective := l.IneffectiveDate.IsZero() || c.NotBefore.Before(l.IneffectiveDate)
	return onOrAfterEffective && strictlyBeforeIneffective
}

// Execute runs the lint against a certificate. For lints that are
// sourced from the CA/B Forum Baseline Requirements, we first determine
// if they are within the purview of the BRs. See LintInterface for details
// about the other methods called. The ordering is as follows:
//
// Configure() ----> only if the lint implements Configurable
// CheckApplies()
// CheckEffective()
// Execute()
func (l *Lint) Execute(cert *x509.Certificate, config Configuration) *LintResult {
	if l.Source == CABFBaselineRequirements && !util.IsServerAuthCert(cert) {
		return &LintResult{Status: NA}
	}
	return l.execute(l.Lint(), cert, config)
}

func (l *Lint) execute(lint LintInterface, cert *x509.Certificate, config Configuration) *LintResult {
	configurable, ok := lint.(Configurable)
	if ok {
		err := config.Configure(configurable.Configure(), l.Name)
		if err != nil {
			details := fmt.Sprintf(
				"A fatal error occurred while attempting to configure %s. Please visit the [%s] section of "+
					"your provided configuration and compare it with the output of `zlint -exampleConfig`. Error: %s",
				l.Name,
				l.Name,
				err.Error())
			return &LintResult{
				Status:  Fatal,
				Details: details}
		}
	}
	if !lint.CheckApplies(cert) {
		return &LintResult{Status: NA}
	} else if !l.CheckEffective(cert) {
		return &LintResult{Status: NE}
	}
	res := lint.Execute(cert)
	return res
}
