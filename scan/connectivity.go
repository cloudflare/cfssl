package scan

import (
	"bufio"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
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

var cloudflareNets []*net.IPNet

func init() {
	// Download CloudFlare CIDR ranges and parse them.
	v4resp, err := http.Get("https://www.cloudflare.com/ips-v4")
	if err != nil {
		log.Fatalf("Couldn't download CloudFlare IPs: %v", err)
	}
	defer v4resp.Body.Close()

	v6resp, err := http.Get("https://www.cloudflare.com/ips-v6")
	if err != nil {
		log.Fatalf("Couldn't download CloudFlare IPs: %v", err)
	}
	defer v6resp.Body.Close()

	scanner := bufio.NewScanner(io.MultiReader(v4resp.Body, strings.NewReader("\n"), v6resp.Body))
	for scanner.Scan() {
		_, ipnet, err := net.ParseCIDR(scanner.Text())
		if err != nil {
			log.Fatalf("Couldn't parse CIDR range: %v", err)
		}
		cloudflareNets = append(cloudflareNets, ipnet)
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("Couldn't read IP bodies: %v", err)
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
