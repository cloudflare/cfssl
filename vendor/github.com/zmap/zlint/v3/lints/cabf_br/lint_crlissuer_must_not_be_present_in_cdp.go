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

package cabf_br

import (
	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_crlissuer_must_not_be_present_in_cdp",
			Description:   "crlIssuer and/or Reason field MUST NOT be present in the CDP extension.",
			Citation:      "BR Section 7.1.2.11.2",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.SC62EffectiveDate,
		},
		Lint: NewCrlissuerMustNotBePresentInCdp,
	})
}

type CrlissuerMustNotBePresentInCdp struct{}

func NewCrlissuerMustNotBePresentInCdp() lint.LintInterface {
	return &CrlissuerMustNotBePresentInCdp{}
}

func (l *CrlissuerMustNotBePresentInCdp) CheckApplies(c *x509.Certificate) bool {
	return c.CRLDistributionPoints != nil
}

func (l *CrlissuerMustNotBePresentInCdp) Execute(c *x509.Certificate) *lint.LintResult {

	for _, ext := range c.Extensions {
		if ext.Id.Equal(util.CrlDistOID) {
			var cdp []distributionPoint
			_, err := asn1.Unmarshal(ext.Value, &cdp)
			if err != nil {
				return &lint.LintResult{Status: lint.Fatal}
			}
			for _, dp := range cdp {
				if (len(dp.CRLIssuer.Bytes) > 0) || (len(dp.Reason.Bytes) > 0) {
					return &lint.LintResult{Status: lint.Error}
				}

			}

		}
	}

	return &lint.LintResult{Status: lint.Pass}
}

type distributionPoint struct {
	DistributionPoint distributionPointName `asn1:"optional,tag:0"`
	Reason            asn1.BitString        `asn1:"optional,tag:1"`
	CRLIssuer         asn1.RawValue         `asn1:"optional,tag:2"`
}

type distributionPointName struct {
	FullName     asn1.RawValue    `asn1:"optional,tag:0"`
	RelativeName pkix.RDNSequence `asn1:"optional,tag:1"`
}
