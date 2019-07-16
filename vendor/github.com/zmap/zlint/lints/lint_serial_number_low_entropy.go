package lints

/*
 * ZLint Copyright 2018 Regents of the University of Michigan
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
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
)

type serialNumberLowEntropy struct{}

func (l *serialNumberLowEntropy) Initialize() error {
	return nil
}

func (l *serialNumberLowEntropy) CheckApplies(c *x509.Certificate) bool {
	return true
}

func (l *serialNumberLowEntropy) Execute(c *x509.Certificate) *LintResult {
	if len(c.SerialNumber.Bytes()) < 8 {
		return &LintResult{Status: Warn}
	} else {
		return &LintResult{Status: Pass}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "w_serial_number_low_entropy",
		Description:   "Effective September 30, 2016, CAs SHALL generate non‐sequential Certificate serial numbers greater than zero (0) containing at least 64 bits of output from a CSPRNG.",
		Citation:      "BRs: 7.1",
		Source:        CABFBaselineRequirements,
		EffectiveDate: util.CABSerialNumberEntropyDate,
		Lint:          &serialNumberLowEntropy{},
	})
}
