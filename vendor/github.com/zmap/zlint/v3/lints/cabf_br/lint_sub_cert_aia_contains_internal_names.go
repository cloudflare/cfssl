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
	"net"
	"net/url"
	"time"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type subCertAIAInternalName struct{}

/************************************************************************
BRs: 7.1.2.10.3
CA Certificate Authority Information Access
This extension MAY be present. If present, it MUST NOT be marked critical, and it MUST contain the
HTTP URL of the CA’s CRL service.

id-ad-ocsp        A HTTP URL of the Issuing CA's OCSP responder.
id-ad-caIssuers   A HTTP URL of the Issuing CA's Certificate.
*************************************************************************/

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "w_sub_cert_aia_contains_internal_names",
			Description:   "Subscriber certificates authorityInformationAccess extension should contain the HTTP URL of the issuing CA’s certificate, for public certificates this should not be an internal name",
			Citation:      "BRs: 7.1.2.10.3",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.CABEffectiveDate,
		},
		Lint: NewSubCertAIAInternalName,
	})
}

func NewSubCertAIAInternalName() lint.LintInterface {
	return &subCertAIAInternalName{}
}

func (l *subCertAIAInternalName) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c) && util.IsExtInCert(c, util.AiaOID)
}

func (l *subCertAIAInternalName) Execute(c *x509.Certificate) *lint.LintResult {
	for _, u := range c.OCSPServer {
		purl, err := url.Parse(u)
		if err != nil {
			return &lint.LintResult{Status: lint.Error}
		}

		if net.ParseIP(purl.Host) != nil {
			continue
		}

		if !util.HasValidTLD(purl.Hostname(), time.Now()) {
			return &lint.LintResult{Status: lint.Warn}
		}
	}
	for _, u := range c.IssuingCertificateURL {
		purl, err := url.Parse(u)
		if err != nil {
			return &lint.LintResult{Status: lint.Error}
		}

		if net.ParseIP(purl.Host) != nil {
			continue
		}

		if !util.HasValidTLD(purl.Hostname(), time.Now()) {
			return &lint.LintResult{Status: lint.Warn}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
