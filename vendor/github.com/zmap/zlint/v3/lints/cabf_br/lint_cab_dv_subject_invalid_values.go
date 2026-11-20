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
	"fmt"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type dvSubjectInvalidValues struct{}

/************************************************
7.1.2.7.2 Domain Validated

The following table details the acceptable AttributeTypes that may appear within the type
field of an AttributeTypeAndValue, as well as the contents permitted within the value field.

Table 35: Domain Validated subject Attributes

countryName MAY The two‐letter ISO 3166‐1 country code for the country
associated with the Subject. Section 3.2.2.3

commonName NOT RECOMMENDED
If present, MUST contain a value derived from the
subjectAltName extension according to Section
7.1.4.3.

Any other attribute MUST NOT
************************************************/

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_cab_dv_subject_invalid_values",
			Description:   "If certificate policy 2.23.140.1.2.1 (CA/B BR domain validated) is included, only country and/or common name is allowed in SubjectDN.",
			Citation:      "BRs: 7.1.2.7.2",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.SC62EffectiveDate,
		},
		Lint: NewDvSubjectInvalidValues,
	})
}

func NewDvSubjectInvalidValues() lint.LintInterface {
	return &dvSubjectInvalidValues{}
}

func (l *dvSubjectInvalidValues) CheckApplies(cert *x509.Certificate) bool {
	return util.SliceContainsOID(cert.PolicyIdentifiers, util.BRDomainValidatedOID) && util.IsSubscriberCert(cert)
}

func (l *dvSubjectInvalidValues) Execute(cert *x509.Certificate) *lint.LintResult {
	names := util.GetTypesInName(&cert.Subject)
	var cnFound = false
	for _, n := range names {
		if n.Equal(util.CommonNameOID) {
			cnFound = true
			continue
		}
		if n.Equal(util.CountryNameOID) {
			continue
		}
		return &lint.LintResult{Status: lint.Error, Details: fmt.Sprintf("DV certificate contains the invalid attribute type %s", n)}
	}

	if cnFound {
		return &lint.LintResult{Status: lint.Warn, Details: "DV certificate contains a subject common name, this is not recommended."}
	}

	return &lint.LintResult{Status: lint.Pass}
}
