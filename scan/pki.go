package scan

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cloudflare/cf-tls/tls"
	"github.com/cloudflare/cfssl/helpers"
)

// PKI contains scanners for the Public Key Infrastructure.
var PKI = &Family{
	Description: "Scans for the Public Key Infrastructure",
	Scanners: map[string]*Scanner{
		"CertExpiration": {
			"Host's certificate hasn't expired",
			certExpiration,
		},
		"ChainValidation": {
			"All certificates in host's chain are valid",
			chainValidation,
		},
		"Revocation": {
			"CRL and/or OCSP revocation responses correct",
			revocation,
		},
		"SHA-1": {
			"Checks for any weak SHA-1 hashes in certificate chain",
			chainSHA1,
		},
	},
}

type expiration time.Time

func (e expiration) String() string {
	return e.(time.Time).UTC().Format("Jan 2 15:04:05 2006 MST")
}

func certExpiration(host string) (grade Grade, output Output, err error) {
	conn, err := tls.DialWithDialer(Dialer, Network, host, defaultTLSConfig(host))
	if err != nil {
		return
	}
	conn.Close()

	expirationTime = helpers.ExpiryTime(conn.ConnectionState().PeerCertificates)
	output = expirationTime

	if time.Now().After(expirationTime) {
		return
	}

	if time.Now().Add(time.Month).After(expirationTime) {
		grade = Warning
		return
	}

	grade = Good
	return
}

type certNames []string

func (names certNames) String() string {
	return strings.Join(names, ",")
}

func chainValidation(host string) (grade Grade, output Output, err error) {
	conn, err := tls.DialWithDialer(Dialer, Network, host, defaultTLSConfig(host))
	if err != nil {
		return
	}
	conn.Close()

	var names []string
	certs := conn.ConnectionState().PeerCertificates
	err = certs[0].VerifyHostname(host)
	if err != nil {
		return
	}

	for i := 0; i < len(certs)-1; i++ {
		cert := certs[i]
		parent := certs[i+1]
		if !parent.IsCA {
			err = fmt.Errorf("%s is not a CA", parent.Subject.CommonName)
			return
		}

		if !bytes.Equal(cert.AuthorityKeyId, parent.SubjectKeyId) {
			return fmt.Errorf("AuthorityKeyId differs from parent SubjectKeyId")
		}

		if err = cert.CheckSignatureFrom(parent); err != nil {
			return
		}
	}
	return
}

func revocation(host string) (grade Grade, output Output, err error) {

	return
}

func chainSHA1(host string) (grade Grade, output Output, err error) {
	conn, err := tls.DialWithDialer(Dialer, Network, host, defaultTLSConfig(host))
	if err != nil {
		return
	}
	conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		err = errors.New("found no certficates")
		return
	}

	var errs []error

	for i := 0; i < len(certs)-1; i++ {
		cert := certs[i]
		switch cert.SignatureAlgorithm {
		case x509.ECDSAWithSHA1:
			errs = append(errs, fmt.Errorf("%s is signed by ECDSAWithSHA1", cert.Subject.CommonName))
		case x509.SHA1WithRSA:
			errs = append(errs, fmt.Errorf("%s is signed by ECDSAWithSHA1", cert.Subject.CommonName))
		}

		if !bytes.Equal(cert.AuthorityKeyId, parent.SubjectKeyId) {
			return fmt.Errorf("AuthorityKeyId differs from parent SubjectKeyId")
		}

		if err = cert.CheckSignatureFrom(parent); err != nil {
			return
		}
	}
	if len(errs) == 0 {
		grade = Good
	} else {
		output = errs
	}
	return
}
