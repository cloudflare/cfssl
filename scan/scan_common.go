package scan

import (
	"crypto/x509"
	"net"
	"net/http"
	"regexp"
	"time"

	"github.com/cloudflare/cf-tls/tls"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
)

var (
	// Network is the default network to use.
	Network = "tcp"
	// Dialer is the default dialer to use, with a 1s timeout.
	Dialer = &net.Dialer{Timeout: time.Second}
	// Client is the default HTTP Client.
	Client = &http.Client{Transport: &http.Transport{Dial: Dialer.Dial}}
	// RootCAs defines the default root certificate authorities to be used for scan.
	RootCAs *x509.CertPool
)

// Grade gives a subjective rating of the host's success in a scan.
type Grade int

const (
	// Bad describes a host with serious misconfiguration or vulnerability.
	Bad Grade = iota
	// Warning describes a host with non-ideal configuration that maintains support for Warning clients.
	Warning
	// Good describes host performing the expected state-of-the-art.
	Good
	// Skipped descibes the "grade" of a scan that has been skipped.
	Skipped
)

// String gives the name of the Grade as a string.
func (g Grade) String() string {
	switch g {
	case Bad:
		return "Bad"
	case Warning:
		return "Warning"
	case Good:
		return "Good"
	case Skipped:
		return "Skipped"
	default:
		return "Invalid"
	}
}

// Output is the result of a scan, to be stored for potential use by later Scanners.
type Output interface{}

// multiscan scans all DNS addresses returned for the host, returning the lowest grade
// and the concatenation of all the output.
func multiscan(host string, scan func(string) (Grade, Output, error)) (grade Grade, output Output, err error) {
	domain, port, _ := net.SplitHostPort(host)
	var addrs []string
	addrs, err = net.LookupHost(domain)
	if err != nil {
		return
	}

	grade = Good
	out := make(map[string]Output)

	for _, addr := range addrs {
		var g Grade
		var o Output

		g, o, err = scan(net.JoinHostPort(addr, port))
		if err != nil {
			grade = Bad
			return
		}

		if g < grade {
			grade = g
		}

		out[addr] = o
	}
	output = out
	return
}

// Scanner describes a type of scan to perform on a host.
type Scanner struct {
	// Description describes the nature of the scan to be performed.
	Description string `json:"description"`
	// scan is the function that scans the given host and provides a Grade and Output.
	scan func(string, string) (Grade, Output, error)
}

// Scan performs the scan to be performed on the given host and stores its result.
func (s *Scanner) Scan(addr, hostname string) (Grade, Output, error) {
	grade, output, err := s.scan(addr, hostname)
	if err != nil {
		log.Infof("scan: %v", err)
		return grade, output, err
	}
	return grade, output, err
}

// Family defines a set of related scans meant to be run together in sequence.
type Family struct {
	// Description gives a short description of the scans performed scan/scan_common.goon the host.
	Description string `json:"description"`
	// Scanners is a list of scanners that are to be run in sequence.
	Scanners map[string]*Scanner `json:"scanners"`
}

// FamilySet contains a set of Families to run Scans from.
type FamilySet map[string]*Family

// Default contains each scan Family that is defined
var Default = FamilySet{
	"Connectivity": Connectivity,
	"TLSHandshake": TLSHandshake,
	"TLSSession":   TLSSession,
	"PKI":          PKI,
	"Broad":        Broad,
}

// ScannerResult contains the result for a single scan.
type ScannerResult struct {
	Grade  string `json:"grade"`
	Output Output `json:"output,omitempty"`
	Error  string `json:"error,omitempty"`
}

// FamilyResult contains a scan response for a single Family
type FamilyResult map[string]ScannerResult

// RunScans iterates over AllScans, running scans matching the family and scanner
// regular expressions.
func (fs FamilySet) RunScans(host, ip, family, scanner string, dur time.Duration) (map[string]FamilyResult, error) {
	hostname, port, err := net.SplitHostPort(host)
	if err != nil {
		hostname = host
		port = "443"
	}

	var addr string
	if net.ParseIP(ip) != nil {
		addr = net.JoinHostPort(ip, port)
	} else {
		addr = net.JoinHostPort(hostname, port)
	}

	familyRegexp, err := regexp.Compile(family)
	if err != nil {
		return nil, err
	}

	scannerRegexp, err := regexp.Compile(scanner)
	if err != nil {
		return nil, err
	}

	results := make(chan map[string]FamilyResult)
	timeout := make(chan bool)

	if dur > 0 {
		go startTimer(dur, timeout)
	}

	familyResults := make(map[string]FamilyResult)

	go func() {
		for familyName, family := range fs {
			if familyRegexp.MatchString(familyName) {
				scannerResults := make(map[string]ScannerResult)
				for scannerName, scanner := range family.Scanners {
					if scannerRegexp.MatchString(scannerName) {
						grade, output, err := scanner.Scan(addr, hostname)
						if grade != Skipped {
							result := ScannerResult{
								Grade:  grade.String(),
								Output: output,
							}
							if err != nil {
								result.Error = err.Error()
							}

							scannerResults[scannerName] = result
						}
					}
				}

				if len(scannerResults) > 0 {
					familyResults[familyName] = scannerResults
				}
			}
		}
		results <- familyResults
	}()

	select {
	case <-timeout:
		log.Warningf("scan: %s timed out after %v", host, dur)
		return familyResults, nil
	case res := <-results:
		return res, nil
	}
}

func startTimer(t time.Duration, timeout chan bool) {
	time.AfterFunc(t, func() {
		timeout <- true
	})
}

// LoadRootCAs loads the default root certificate authorities from file.
func LoadRootCAs(caBundleFile string) (err error) {
	if caBundleFile != "" {
		log.Debugf("Loading scan RootCAs: %s", caBundleFile)
		RootCAs, err = helpers.LoadPEMCertPool(caBundleFile)
	}
	return
}

func defaultTLSConfig(hostname string) *tls.Config {
	return &tls.Config{
		ServerName:         hostname,
		RootCAs:            RootCAs,
		InsecureSkipVerify: true,
	}
}
