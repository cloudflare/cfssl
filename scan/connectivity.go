package scan

import (
	"errors"
	"net"
	"strings"

	"github.com/cloudflare/cf-tls/tls"
)

// Connectivity contains scanners testing basic connectivity to the host
var Connectivity = &Family{
	Description: "Scans for basic connectivity with the host through DNS and TCP/TLS dials",
	Scanners: map[string]*Scanner{
		"DNSLookup": {
			"Host can be resolved through DNS",
			dnsLookupScan,
		},
		"TCPDial": {
			"Host accepts TCP connection",
			tcpDialScan,
		},
		"TLSDial": {
			"Host can perform TLS handshake",
			tlsDialScan,
		},
	},
}

// lookupAddrs is a list of host's addresses returned by DNS lookup
type lookupAddrs []string

func (addrs lookupAddrs) String() string {
	return strings.Join(addrs, "\n")
}

// dnsLookupScan tests that DNS resolution of the host returns at least one address
func dnsLookupScan(host string) (grade Grade, output Output, err error) {
	host, _, err = net.SplitHostPort(host)
	if err != nil {
		return
	}

	var addrs lookupAddrs
	addrs, err = net.LookupHost(host)
	if err != nil {
		return
	}

	if len(addrs) == 0 {
		err = errors.New("no addresses found for host")
	}
	grade, output = Good, addrs
	return
}

// tcpDialScan tests that the host can be connected to through TCP.
func tcpDialScan(host string) (grade Grade, output Output, err error) {
	conn, err := Dialer.Dial(Network, host)
	if err != nil {
		return
	}
	conn.Close()
	grade = Good
	return
}

// tlsDialScan tests that the host can perform a TLS Handshake.
func tlsDialScan(host string) (grade Grade, output Output, err error) {
	conn, err := tls.DialWithDialer(Dialer, Network, host, defaultTLSConfig(host))
	if err != nil {
		return
	}
	conn.Close()
	grade = Good
	return
}
