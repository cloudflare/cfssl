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

/*************************************************************************
7.1.4.2.1 Subject alternative name extension

All Mailbox Addresses in the subject field or entries of type dirName of this extension SHALL be
repeated as rfc822Name or otherName values of type id-on-SmtpUTF8Mailbox in this
extension.

7.1.4.2.2 Subject distinguished name fields

h. Certificate Field: subject:emailAddress (1.2.840.113549.1.9.1) Contents: If present, the
subject:emailAddress SHALL contain a single Mailbox Address as verified under
Section 3.2.2.

Combining these requirements, this lint checks for malformed email addresses in SAN entries
covering the case of a non-single Mailbox Address.
*************************************************************************/

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_single_email_if_present",
			Description:   "If present, the subject:emailAddress SHALL contain a single Mailbox Address. All Mailbox Addresses in the subject field SHALL be repeated as rfc822Name or otherName values of type id-on-SmtpUTF8Mailbox in SAN extension.",
			Citation:      "7.1.4.2.1 and 7.1.4.2.2.h",
			Source:        lint.CABFSMIMEBaselineRequirements,
			EffectiveDate: util.CABF_SMIME_BRs_1_0_0_Date,
		},
		Lint: NewSingleEmailIfPresent,
	})
}

type singleEmailIfPresent struct{}

func NewSingleEmailIfPresent() lint.LintInterface {
	return &singleEmailIfPresent{}
}

func (l *singleEmailIfPresent) CheckApplies(c *x509.Certificate) bool {
	addresses := c.EmailAddresses
	return util.IsSubscriberCert(c) && addresses != nil && len(addresses) != 0 && util.IsSMIMEBRCertificate(c)
}

func (l *singleEmailIfPresent) Execute(c *x509.Certificate) *lint.LintResult {
	for _, email := range c.EmailAddresses {
		if _, err := mail.ParseAddress(email); err != nil {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: fmt.Sprintf("san:emailAddress was present and contained an invalid email address (%s)", email),
			}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
