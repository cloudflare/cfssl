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
			Name:          "e_legal_entity_identifier",
			Description:   "Mailbox/individual: prohibited. Organization/sponsor: may be present",
			Citation:      "7.1.2.3.l",
			Source:        lint.CABFSMIMEBaselineRequirements,
			EffectiveDate: util.CABF_SMIME_BRs_1_0_0_Date,
		},
		Lint: NewLegalEntityIdentifier,
	})
}

type legalEntityIdentifier struct{}

func NewLegalEntityIdentifier() lint.LintInterface {
	return &legalEntityIdentifier{}
}

func (l *legalEntityIdentifier) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c) && util.IsSMIMEBRCertificate(c)
}

func (l *legalEntityIdentifier) Execute(c *x509.Certificate) *lint.LintResult {
	leiPresent := util.IsExtInCert(c, util.LegalEntityIdentifierOID)
	leiExt := util.GetExtFromCert(c, util.LegalEntityIdentifierOID)
	leiRolePresent := util.IsExtInCert(c, util.LegalEntityIdentifierRoleOID)
	leiRoleExt := util.GetExtFromCert(c, util.LegalEntityIdentifierRoleOID)

	switch {
	case util.IsMailboxValidatedCertificate(c), util.IsIndividualValidatedCertificate(c):
		if leiPresent {
			// Mailbox-validated and Individual-validated prohibited.
			return &lint.LintResult{Status: lint.Error, Details: "Legal Entity Identifier extension present"}
		}
	case util.IsOrganizationValidatedCertificate(c):
		if leiPresent && leiExt.Critical {
			// LEI (1.3.6.1.4.1.52266.1) MAY be present and SHALL NOT be marked critical.
			return &lint.LintResult{Status: lint.Error, Details: "Legal Entity Identifier extension present and critical"}
		}
		if leiRolePresent {
			// This is affirming the negative. Sponsor validated certificates MAY have an LEI Role, so
			// it is being taken here that not explicitly as such for organization validated certificates
			// implies that they are not allowed.
			return &lint.LintResult{Status: lint.Error, Details: "Legal Entity Identifier Role extension present"}
		}
	case util.IsSponsorValidatedCertificate(c):
		if leiPresent && leiExt.Critical {
			// LEI (1.3.6.1.4.1.52266.1) MAY be present and SHALL NOT be marked critical.
			return &lint.LintResult{Status: lint.Error, Details: "Legal Entity Identifier extension present and critical"}
		}
		if leiRolePresent && leiRoleExt.Critical {
			// LEI Role (1.3.6.1.4.1.52266.2) MAY be present and SHALL NOT be marked critical.
			return &lint.LintResult{Status: lint.Error, Details: "Legal Entity Identifier Role extension present and critical"}
		}
	default:
		return &lint.LintResult{Status: lint.Error, Details: "Unknown validation type"}
	}

	return &lint.LintResult{Status: lint.Pass}
}
