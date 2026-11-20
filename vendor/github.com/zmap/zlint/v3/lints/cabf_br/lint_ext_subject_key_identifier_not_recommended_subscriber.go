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

type subjectKeyIdNotRecommendedSubscriber struct{}

/**********************************************************************
RFC5280 suggested the addition of SKI extension, but CABF BR SC62
marked the extension as NOT RECOMMENDED for subscriber certificates

Warning:
Users of zlint will trigger either
`w_ext_subject_key_identifier_not_recommended_subscriber` (this lint)
or `w_ext_subject_key_identifier_missing_sub_cert` the one enforcing
RFC5280's behavior.

Users are expected to specifically ignore one or the other lint
depending on which one apply to them.

See:
 - https://github.com/zmap/zlint/issues/749
 - https://github.com/zmap/zlint/issues/762
**********************************************************************/

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "w_ext_subject_key_identifier_not_recommended_subscriber",
			Description:   "Subscriber certificates use of Subject Key Identifier is NOT RECOMMENDED",
			Citation:      "BRs v2: 7.1.2.7.6",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.SC62EffectiveDate,
		},
		Lint: NewSubjectKeyIdNotRecommendedSubscriber,
	})
}

func NewSubjectKeyIdNotRecommendedSubscriber() lint.LintInterface {
	return &subjectKeyIdNotRecommendedSubscriber{}
}

func (l *subjectKeyIdNotRecommendedSubscriber) CheckApplies(cert *x509.Certificate) bool {
	return util.IsSubscriberCert(cert)
}

func (l *subjectKeyIdNotRecommendedSubscriber) Execute(cert *x509.Certificate) *lint.LintResult {
	if util.IsExtInCert(cert, util.SubjectKeyIdentityOID) {
		return &lint.LintResult{Status: lint.Warn}
	} else {
		return &lint.LintResult{Status: lint.Pass}
	}
}
