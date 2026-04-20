package util

import (
	"net/mail"

	"github.com/zmap/zcrypto/x509"
)

func HasEmailSAN(c *x509.Certificate) bool {
	for _, san := range c.EmailAddresses {
		if san != "" {
			return true
		}
	}

	for _, name := range c.OtherNames {
		if name.TypeID.Equal(OidIdOnSmtpUtf8Mailbox) && len(name.Value.Bytes) != 0 {
			return true
		}
	}

	return false
}

// IsMailboxAddress returns true if the passed in string resembles an RFC 5322
// mailbox address.
func IsMailboxAddress(address string) bool {
	validAddress, err := mail.ParseAddress(address)
	return err == nil && validAddress.Address == address
}
