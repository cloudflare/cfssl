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
	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

// MailboxAddressFromSAN - linter to enforce MAY/SHALL NOT requirements for SMIME certificates
type MailboxAddressFromSAN struct {
}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_mailbox_address_shall_contain_an_rfc822_name",
		Description:   "All Mailbox Addresses in the subject field or entries of type dirName of this extension SHALL be repeated as rfc822Name or otherName values of type id-on-SmtpUTF8Mailbox in this extension",
		Citation:      "SMIME BRs: 7.1.4.2.1",
		Source:        lint.CABFSMIMEBaselineRequirements,
		EffectiveDate: util.CABF_SMIME_BRs_1_0_0_Date,
		Lint:          NewMailboxAddressFromSAN,
	})
}

// NewMailboxAddressFromSAN creates a new linter to enforce the requirement that all Mailbox Addresses in SMIME BR certificates must be copied from the SAN
func NewMailboxAddressFromSAN() lint.LintInterface {
	return &MailboxAddressFromSAN{}
}

// CheckApplies is returns true if the certificate's policies assert that it conforms to the SMIME BRs
func (l *MailboxAddressFromSAN) CheckApplies(c *x509.Certificate) bool {

	if !(util.IsSMIMEBRCertificate(c) && util.IsSubscriberCert(c)) {
		return false
	}

	toFindMailboxAddresses := getMailboxAddressesFromDistinguishedName(c.Subject, util.IsMailboxValidatedCertificate(c))

	for _, dirName := range c.DirectoryNames {
		toFindMailboxAddresses = append(toFindMailboxAddresses, getMailboxAddressesFromDistinguishedName(dirName, false)...)
	}

	return len(toFindMailboxAddresses) > 0

}

// Execute checks all the places where Mailbox Addresses may be found in an SMIME certificate and confirms that they are present in the SAN rfc822Name or SAN otherName
func (l *MailboxAddressFromSAN) Execute(c *x509.Certificate) *lint.LintResult {
	lintErr := &lint.LintResult{
		Status:  lint.Error,
		Details: "all certificate mailbox addresses must be present in san:emailAddresses or san:otherNames in addition to any other field they may appear",
	}

	// build list of Mailbox addresses from subject:commonName, subject:emailAddress, dirName

	toFindMailboxAddresses := getMailboxAddressesFromDistinguishedName(c.Subject, util.IsMailboxValidatedCertificate(c))

	for _, dirName := range c.DirectoryNames {
		toFindMailboxAddresses = append(toFindMailboxAddresses, getMailboxAddressesFromDistinguishedName(dirName, false)...)
	}

	sanNames := map[string]bool{}
	for _, rfc822Name := range c.EmailAddresses {
		sanNames[rfc822Name] = true
	}

	for _, otherName := range c.OtherNames {
		if otherName.TypeID.Equal(util.OidIdOnSmtpUtf8Mailbox) {
			// The otherName needs to be specially unmarshalled since it is
			// stored as a UTF-8 string rather than what the asn1 package
			// describes as a PrintableString.
			var otherNameValue string
			rest, err := asn1.UnmarshalWithParams(otherName.Value.Bytes, &otherNameValue, "utf8")
			if len(rest) > 0 || err != nil {
				return lintErr
			}

			sanNames[otherNameValue] = true
		}
	}

	for _, mailboxAddress := range toFindMailboxAddresses {
		if _, found := sanNames[mailboxAddress]; !found {
			return lintErr
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}

func getMailboxAddressesFromDistinguishedName(name pkix.Name, includeCN bool) []string {
	mailboxAddresses := []string{}

	if includeCN {
		for _, commonName := range name.CommonNames {
			if util.IsMailboxAddress(commonName) {
				mailboxAddresses = append(mailboxAddresses, commonName)
			}
		}
	}

	for _, emailAddress := range name.EmailAddress {
		if util.IsMailboxAddress(emailAddress) {
			mailboxAddresses = append(mailboxAddresses, emailAddress)
		}
	}

	return mailboxAddresses
}
