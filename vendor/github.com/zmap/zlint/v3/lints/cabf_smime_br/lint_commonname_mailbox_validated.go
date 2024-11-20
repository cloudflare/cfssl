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
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_commonname_mailbox_validated",
			Description:   "If present, the commonName attribute of a mailbox-validated certificate SHALL contain a mailbox address",
			Citation:      "S/MIME BRs: 7.1.4.2.2a",
			Source:        lint.CABFSMIMEBaselineRequirements,
			EffectiveDate: util.CABF_SMIME_BRs_1_0_0_Date,
		},
		Lint: NewCommonNameMailboxValidated,
	})
}

type commonNameMailboxValidated struct{}

func NewCommonNameMailboxValidated() lint.LintInterface {
	return &commonNameMailboxValidated{}
}

func (l *commonNameMailboxValidated) CheckApplies(c *x509.Certificate) bool {
	return util.IsMailboxValidatedCertificate(c)
}

func (l *commonNameMailboxValidated) Execute(c *x509.Certificate) *lint.LintResult {
	commonNames := []string{c.Subject.CommonName}
	commonNames = append(commonNames, c.Subject.CommonNames...)
	for _, cn := range commonNames {
		if !util.IsMailboxAddress(cn) {
			return &lint.LintResult{Status: lint.Error}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
