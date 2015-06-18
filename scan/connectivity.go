package scan

import (
	"errors"
	"log"
	"net"

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
		"CloudFlareStatus": {
			"Host is on CloudFlare",
			onCloudFlareScan,
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

var cloudflareIPs = [...]string{
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"104.16.0.0/12",
	"108.162.192.0/18",
	"141.101.64.0/18",
	"162.158.0.0/15",
	"172.64.0.0/13",
	"173.245.48.0/20",
	"188.114.96.0/20",
	"190.93.240.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"199.27.128.0/21",

	"2400:cb00::/32",
	"2405:8100::/32",
	"2405:b500::/32",
	"2606:4700::/32",
	"2803:f800::/32",
}

var cloudflareNets []*net.IPNet

func init() {
	for _, s := range cloudflareIPs {
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			log.Fatalf("Couldn't parse CIDR range: %v", err)
		}
		cloudflareNets = append(cloudflareNets, ipnet)
	}
}

// dnsLookupScan tests that DNS resolution of the host returns at least one address
func dnsLookupScan(host string) (grade Grade, output Output, err error) {
	host, _, err = net.SplitHostPort(host)
	if err != nil {
		return
	}

	addrs, err := net.LookupHost(host)
	if err != nil {
		return
	}

	if len(addrs) == 0 {
		err = errors.New("no addresses found for host")
	}

	grade, output = Good, addrs
	return
}

func onCloudFlareScan(host string) (grade Grade, output Output, err error) {
	_, addrs, err := dnsLookupScan(host)
	if err != nil {
		return
	}

	cfStatus := make(map[string]bool)
	grade = Good
	for _, addr := range addrs.([]string) {
		ip := net.ParseIP(addr)
		for _, cfNet := range cloudflareNets {
			if cfNet.Contains(ip) {
				cfStatus[addr] = true
				break
			}
		}
		if !cfStatus[addr] {
			cfStatus[addr] = false
			grade = Bad
		}
	}

	output = cfStatus
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
