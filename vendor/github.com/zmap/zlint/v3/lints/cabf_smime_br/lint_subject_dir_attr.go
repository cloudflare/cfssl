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
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type subDirAttr struct{}

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_strict_multipurpose_smime_ext_subject_directory_attr",
			Description:   "SMIME Strict and Multipurpose certificates cannot have Subject Directory Attributes",
			Citation:      "BRs: 7.1.2.3j",
			Source:        lint.CABFSMIMEBaselineRequirements,
			EffectiveDate: util.CABF_SMIME_BRs_1_0_0_Date,
		},
		Lint: NewSubDirAttr,
	})
}

func NewSubDirAttr() lint.LintInterface {
	return &subDirAttr{}
}

func (l *subDirAttr) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c) && (util.IsStrictSMIMECertificate(c) || util.IsMultipurposeSMIMECertificate(c))
}

func (l *subDirAttr) Execute(c *x509.Certificate) *lint.LintResult {
	if util.IsExtInCert(c, util.SubjectDirAttrOID) {
		return &lint.LintResult{Status: lint.Error}
	} else {
		return &lint.LintResult{Status: lint.Pass}
	}
}
