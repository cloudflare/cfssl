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

/*
 * Contributed by Adriano Santoni <adriano.santoni@staff.aruba.it>
 * of ACTALIS S.p.A. (www.actalis.com).
 */

package cabf_br

import (
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_invalid_subject_rdn_order",
			Description:   "Subject field attributes (RDNs) SHALL be encoded in a specific order",
			Citation:      "BRs: 7.1.4.2",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.CABFBRs_2_0_0_Date,
		},
		Lint: NewInvalidSubjectRDNOrder,
	})
}

type invalidSubjectRDNOrder struct{}

func NewInvalidSubjectRDNOrder() lint.LintInterface {
	return &invalidSubjectRDNOrder{}
}

func (l *invalidSubjectRDNOrder) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c)
}

func getShortOIDName(oid string) string {
	switch oid {
	case "0.9.2342.19200300.100.1.25":
		return "DC"
	case "2.5.4.6":
		return "C"
	case "2.5.4.8":
		return "ST"
	case "2.5.4.7":
		return "L"
	case "2.5.4.17":
		return "postalCode"
	case "2.5.4.9":
		return "street"
	case "2.5.4.10":
		return "O"
	case "2.5.4.4":
		return "SN"
	case "2.5.4.42":
		return "givenName"
	case "2.5.4.11":
		return "OU"
	case "2.5.4.3":
		return "CN"
	default:
		return ""
	}
}

func findElement(arr []string, target string) (int, bool) {
	for i, value := range arr {
		if value == target {
			return i, true
		}
	}
	return -1, false
}

func checkOrder(actualOrder []string, expectedOrder []string) bool {
	var prevPosition int
	prevPosition = 0

	for _, targetElement := range actualOrder {
		position, found := findElement(expectedOrder, targetElement)
		if found {
			if position < prevPosition {
				return false
			}
			prevPosition = position
		}
	}
	return true
}

func checkSubjectRDNOrder(cert *x509.Certificate) bool {

	rawSubject := cert.RawSubject

	var rdnSequence pkix.RDNSequence
	_, err := asn1.Unmarshal(rawSubject, &rdnSequence)
	if err != nil {
		return false
	}

	var rdnOrder []string

	for _, rdn := range rdnSequence {
		for _, atv := range rdn {
			rdnShortName := getShortOIDName(atv.Type.String())
			if rdnShortName != "" {
				rdnOrder = append(rdnOrder, rdnShortName)
			}
		}
	}

	// Expected order of RDNs as per CABF BR section 7.1.4.2
	expectedRDNOrder := []string{"DC", "C", "ST", "L", "postalCode", "street", "O", "SN", "givenName", "OU", "CN"}

	return checkOrder(rdnOrder, expectedRDNOrder)
}

func (l *invalidSubjectRDNOrder) Execute(c *x509.Certificate) *lint.LintResult {

	var out lint.LintResult

	if checkSubjectRDNOrder(c) {
		out.Status = lint.Pass
	} else {
		out.Status = lint.Error
	}
	return &out
}
