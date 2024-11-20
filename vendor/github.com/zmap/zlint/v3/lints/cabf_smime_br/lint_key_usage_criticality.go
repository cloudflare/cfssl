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
			Name:          "w_key_usage_criticality",
			Description:   "keyUsage... This extension SHOULD be marked critical",
			Citation:      "7.1.2.3.e",
			Source:        lint.CABFSMIMEBaselineRequirements,
			EffectiveDate: util.CABF_SMIME_BRs_1_0_0_Date,
		},
		Lint: NewKeyUsageCriticality,
	})
}

type keyUsageCriticality struct{}

func NewKeyUsageCriticality() lint.LintInterface {
	return &keyUsageCriticality{}
}

func (l *keyUsageCriticality) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c) && util.IsSMIMEBRCertificate(c) && util.IsExtInCert(c, util.KeyUsageOID)

}

func (l *keyUsageCriticality) Execute(c *x509.Certificate) *lint.LintResult {
	kuExt := util.GetExtFromCert(c, util.KeyUsageOID)
	if !kuExt.Critical {
		return &lint.LintResult{Status: lint.Warn}
	}

	return &lint.LintResult{Status: lint.Pass}
}
