package cabf_br

/*
 * ZLint Copyright 2024 Regents of the University of Michigan
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
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type commonNamesSC62 struct{}

/***************************************************************
BRs: 7.1.2.7.1
Required/Optional: NOT RECOMMENDED
***************************************************************/

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "w_subject_common_name_included",
			Description:   "Subscriber Certificate: commonName is NOT RECOMMENDED.",
			Citation:      "BRs: 7.1.2.7.1",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.SC62EffectiveDate,
		},
		Lint: NewCommonNamesSC62,
	})
}

func NewCommonNamesSC62() lint.LintInterface {
	return &commonNamesSC62{}
}

func (l *commonNamesSC62) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c)
}

func (l *commonNamesSC62) Execute(c *x509.Certificate) *lint.LintResult {
	if c.Subject.CommonName == "" {
		return &lint.LintResult{Status: lint.Pass}
	} else {
		return &lint.LintResult{Status: lint.Warn}
	}
}
