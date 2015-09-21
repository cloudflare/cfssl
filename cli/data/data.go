// Package data implements the data command
package data

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/data"
)

// Usage text of 'cfssl data'
var dataUsageText = `cfssl data -- output data about the given cert

Usage of data:
	- Data from local certificate files
        cfssl data -cert file
	- Data from certificate from remote server.
        cfssl data -domain domain_name

Flags:
`

// flags used by 'cfssl data'
var dataFlags = []string{"cert", "domain"}

// dataMain is the main CLI of data functionality
func dataMain(args []string, c cli.Config) (err error) {
	var cert *data.Certificate

	if c.CertFile != "" {
		if c.CertFile == "-" {
			var certPEM []byte
			certPEM, err = cli.ReadStdin(c.CertFile)
			if err != nil {
				return
			}

			cert, err = data.ParseCertificatePEM(certPEM)
			if err != nil {
				return
			}
		} else {
			cert, err = data.ParseCertificateFile(c.CertFile)
			if err != nil {
				return
			}
		}
	} else if c.Domain != "" {
		var host, port string
		if host, port, err = net.SplitHostPort(c.Domain); err != nil {
			host = c.Domain
			port = "443"
		}

		var conn *tls.Conn
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", net.JoinHostPort(host, port), &tls.Config{})
		if err != nil {
			return
		}

		cert = data.ParseCertificate(conn.ConnectionState().PeerCertificates[0])
		conn.Close()
	} else {
		return errors.New("Must specify data target through -cert or -domain")
	}

	var b []byte
	b, err = json.MarshalIndent(cert,"","  ")
	if err != nil {
		return
	}

	fmt.Println(string(b))
	return
}

// Command assembles the definition of Command 'bundle'
var Command = &cli.Command{UsageText: dataUsageText, Flags: dataFlags, Main: dataMain}
