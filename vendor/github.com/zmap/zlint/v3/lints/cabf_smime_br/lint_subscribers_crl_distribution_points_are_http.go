/*
 * ZLint Copyright 2023 Regents of the University of Michigan
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
	"net/url"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_subscribers_crl_distribution_points_are_http",
			Description:   "cRLDistributionPoints SHALL have URI scheme HTTP.",
			Citation:      "7.1.2.3.b",
			Source:        lint.CABFSMIMEBaselineRequirements,
			EffectiveDate: util.CABF_SMIME_BRs_1_0_0_Date,
		},
		Lint: NewSubscriberCrlDistributionPointsHTTP,
	})
}

type subscriberCrlDistributionPointsHTTP struct{}

func NewSubscriberCrlDistributionPointsHTTP() lint.LintInterface {
	return &subscriberCrlDistributionPointsHTTP{}
}

func (l *subscriberCrlDistributionPointsHTTP) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c) && util.IsSMIMEBRCertificate(c)
}

func (l *subscriberCrlDistributionPointsHTTP) Execute(c *x509.Certificate) *lint.LintResult {
	httpCount := 0
	for _, dp := range c.CRLDistributionPoints {
		parsed, err := url.Parse(dp)
		if err != nil {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "SMIME certificate contains invalid CRL distribution point",
			}
		}
		if parsed.Scheme == "http" {
			httpCount++
		}
	}

	if (util.IsMultipurposeSMIMECertificate(c) || util.IsStrictSMIMECertificate(c)) && httpCount != len(c.CRLDistributionPoints) {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "SMIME certificate contains invalid URI scheme in CRL distribution point",
		}
	}
	if util.IsLegacySMIMECertificate(c) && httpCount == 0 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "SMIME certificate contains no HTTP URI schemes as CRL distribution points",
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
