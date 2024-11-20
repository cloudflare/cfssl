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
	"fmt"
	"net/mail"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_single_email_subject_if_present",
			Description:   "If present, the subject:emailAddress SHALL contain a single Mailbox Address",
			Citation:      "7.1.4.2.2.h",
			Source:        lint.CABFSMIMEBaselineRequirements,
			EffectiveDate: util.CABF_SMIME_BRs_1_0_0_Date,
		},
		Lint: NewSingleEmailSubjectIfPresent,
	})
}

type singleEmailSubjectIfPresent struct{}

func NewSingleEmailSubjectIfPresent() lint.LintInterface {
	return &singleEmailSubjectIfPresent{}
}

func (l *singleEmailSubjectIfPresent) CheckApplies(c *x509.Certificate) bool {
	emailAddress := c.Subject.EmailAddress
	return util.IsSubscriberCert(c) && emailAddress != nil && len(emailAddress) != 0 && util.IsSMIMEBRCertificate(c)
}

func (l *singleEmailSubjectIfPresent) Execute(c *x509.Certificate) *lint.LintResult {
	for _, email := range c.Subject.EmailAddress {
		if _, err := mail.ParseAddress(email); err != nil {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: fmt.Sprintf("subject:emailAddress was present and contained an invalid email address (%s)", email),
			}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
