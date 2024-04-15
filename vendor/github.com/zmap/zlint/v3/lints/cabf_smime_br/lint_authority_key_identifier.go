package cabf_smime_br

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
	"fmt"

	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type keyIdentifier struct {
	KeyIdentifier             asn1.RawValue `asn1:"optional,tag:0"`
	AuthorityCertIssuer       asn1.RawValue `asn1:"optional,tag:1"`
	AuthorityCertSerialNumber asn1.RawValue `asn1:"optional,tag:2"`
}

type authorityKeyIdentifierCorrect struct{}

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_authority_key_identifier_correct",
			Description:   "authorityKeyIdentifier SHALL be present. This extension SHALL NOT be marked critical. The keyIdentifier field SHALL be present. authorityCertIssuer and authorityCertSerialNumber fields SHALL NOT be present.",
			Citation:      "7.1.2.3.g",
			Source:        lint.CABFSMIMEBaselineRequirements,
			EffectiveDate: util.CABF_SMIME_BRs_1_0_0_Date,
		},
		Lint: NewAuthorityKeyIdentifierCorrect,
	})
}

func NewAuthorityKeyIdentifierCorrect() lint.LintInterface {
	return &authorityKeyIdentifierCorrect{}
}

func (l *authorityKeyIdentifierCorrect) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c) && util.IsSMIMEBRCertificate(c)
}

func (l *authorityKeyIdentifierCorrect) Execute(c *x509.Certificate) *lint.LintResult {
	ext := util.GetExtFromCert(c, util.AuthkeyOID)
	if ext == nil {
		return &lint.LintResult{Status: lint.Error, Details: "missing authorityKeyIdentifier"}
	}
	if ext.Critical {
		return &lint.LintResult{Status: lint.Error, Details: "authorityKeyIdentifier is critical"}
	}

	var keyID keyIdentifier
	if _, err := asn1.Unmarshal(ext.Value, &keyID); err != nil {
		return &lint.LintResult{
			Status:  lint.Fatal,
			Details: fmt.Sprintf("error unmarshalling authority key identifier extension: %v", err),
		}
	}

	hasKeyID := len(keyID.KeyIdentifier.Bytes) > 0
	hasCertIssuer := len(keyID.AuthorityCertIssuer.Bytes) > 0
	hasCertSerial := len(keyID.AuthorityCertSerialNumber.Bytes) > 0
	if !hasKeyID {
		return &lint.LintResult{Status: lint.Error, Details: "keyIdentifier not present"}
	}
	if hasCertIssuer {
		return &lint.LintResult{Status: lint.Error, Details: "authorityCertIssuer is present"}
	}
	if hasCertSerial {
		return &lint.LintResult{Status: lint.Error, Details: "authorityCertSerialNumber is present"}
	}
	return &lint.LintResult{Status: lint.Pass}
}
