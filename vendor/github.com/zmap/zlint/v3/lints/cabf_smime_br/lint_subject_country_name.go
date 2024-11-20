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

package cabf_smime_br

import (
	"strings"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_subject_country_name",
			Description:   "If present, the subject:countryName SHALL contain the two‐letter ISO 3166‐1 country code associated with the location of the Subject",
			Citation:      "S/MIME BRs: 7.1.4.2.2n",
			Source:        lint.CABFSMIMEBaselineRequirements,
			EffectiveDate: util.CABF_SMIME_BRs_1_0_0_Date,
		},
		Lint: NewSubjectCountryName,
	})
}

type subjectCountryName struct{}

func NewSubjectCountryName() lint.LintInterface {
	return &subjectCountryName{}
}

func (l *subjectCountryName) CheckApplies(c *x509.Certificate) bool {
	return util.IsMailboxValidatedCertificate(c)
}

func (l *subjectCountryName) Execute(c *x509.Certificate) *lint.LintResult {
	for _, cc := range c.Subject.Country {
		if !util.IsISOCountryCode(cc) && strings.ToUpper(cc) != "XX" {
			return &lint.LintResult{Status: lint.Error}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
