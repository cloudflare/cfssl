package scan

import (
	"fmt"
	"net"
	"regexp"
	"time"

	"github.com/cloudflare/cf-tls/tls"
	"github.com/cloudflare/cfssl/log"
)

var (
	// Network is the default network to use.
	Network = "tcp"
	// Dialer is the default dialer to use, with a 1s timeout.
	Dialer = &net.Dialer{Timeout: time.Second}
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
type Output interface {
	fmt.Stringer
}

// Scanner describes a type of scan to perform on a host.
type Scanner struct {
	// Description describes the nature of the scan to be performed.
	Description string `json:"description"`
	// scan is the function that scans the given host and provides a Grade and Output.
	scan func(host string) (Grade, Output, error)
}

// Scan performs the scan to be performed on the given host and stores its result.
func (s *Scanner) Scan(host string) (Grade, Output, error) {
	grade, output, err := s.scan(host)
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
}

// ScannerResult contains the result for a single scan.
type ScannerResult struct {
	Grade  string `json:"grade"`
	Output Output `json:"output,omitempty"`
	Error  error  `json:"error,omitempty"`
}

// FamilyResult contains a scan response for a single Family
type FamilyResult map[string]ScannerResult

// RunScans interates over AllScans, running scans matching the family and scanner
// regular expressions.
func (fs FamilySet) RunScans(host, family, scanner string) (map[string]FamilyResult, error) {
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "443")
	}

	familyRegexp, err := regexp.Compile(family)
	if err != nil {
		return nil, err
	}

	scannerRegexp, err := regexp.Compile(scanner)
	if err != nil {
		return nil, err
	}

	familyResults := make(map[string]FamilyResult)

	for familyName, family := range fs {
		if familyRegexp.MatchString(familyName) {
			scannerResults := make(map[string]ScannerResult)

			for scannerName, scanner := range family.Scanners {
				if scannerRegexp.MatchString(scannerName) {
					grade, output, err := scanner.Scan(host)
					scannerResults[scannerName] = ScannerResult{
						Grade:  grade.String(),
						Output: output,
						Error:  err,
					}
				}
			}

			familyResults[familyName] = scannerResults
		}
	}
	return familyResults, nil
}

func defaultTLSConfig(host string) *tls.Config {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	return &tls.Config{ServerName: h, InsecureSkipVerify: true}
}
