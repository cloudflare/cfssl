package scan

import (
	"errors"
	"net"

	"github.com/cloudflare/cf-tls/tls"
)

// TLSSession contains tests of host TLS Session Resumption via
// Session Tickets and Session IDs
var TLSSession = &Family{
	Description: "Scans host's implementation of TLS session resumption using session tickets/session IDs",
	Scanners: map[string]*Scanner{
		"SessionResume": {
			"Host is able to resume sessions across all addresses",
			sessionResumeScan,
		},
	},
}

// SessionResumeScan tests that host is able to resume sessions across all addresses.
func sessionResumeScan(host string) (grade Grade, output Output, err error) {
	var hostname, port string
	hostname, port, err = net.SplitHostPort(host)
	if err != nil {
		return
	}
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return
	}
	config := defaultTLSConfig(host)
	config.ClientSessionCache = tls.NewLRUClientSessionCache(1)
	var conn *tls.Conn
	conn, err = tls.DialWithDialer(Dialer, Network, host, config)
	if err != nil {
		return
	}
	conn.Close()

	for _, ip := range ips {
		host = net.JoinHostPort(ip.String(), port)
		conn, err = tls.Dial(Network, host, config)
		if err != nil {
			return
		}
		conn.Close()
		if !conn.ConnectionState().DidResume {
			err = errors.New("did not resume")
			return
		}
	}
	grade = Good
	return
}
