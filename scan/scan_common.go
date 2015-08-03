package scan

import (
	"net"
	"net/http"
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
	// Client is the default HTTP Client.
	Client = &http.Client{Transport: &http.Transport{Dial: Dialer.Dial}}
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

type scanFunc func(string) (Grade, Output, error)

// multiscan scans all DNS addresses returned for the host, returning the lowest grade
// and the concatenation of all the output.
func multiscan(host string, scan scanFunc) (grade Grade, output Output, err error) {
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
	scan scanFunc
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

// PackagedFamilyResult contains a FamilyResult and its FamilyName
type PackagedFamilyResult struct {
	Result     FamilyResult
	FamilyName string
}

// RunScans iterates over AllScans, running each scan that matches the family
// and scanner regular expressions concurrently.
func (fs FamilySet) RunScans(host, family, scanner string, resChan chan PackagedFamilyResult, errChan chan error) {
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "443")
	}

	familyRegexp, err := regexp.Compile(family)
	if err != nil {
		errChan <- err
		return
	}

	scannerRegexp, err := regexp.Compile(scanner)
	if err != nil {
		errChan <- err
		return
	}

	for familyName, family := range fs {
		if familyRegexp.MatchString(familyName) {
			done := make(chan bool)
			scannerResults := make(map[string]ScannerResult)

			for scannerName, scanner := range family.Scanners {

				go func(scannerName string, scanner *Scanner, scannerResults map[string]ScannerResult) {
					if scannerRegexp.MatchString(scannerName) {
						grade, output, err := scanner.Scan(host)

						var result ScannerResult
						if err != nil {
							result.Error = err.Error()
							errChan <- err
							return
						}
						result.Grade = grade.String()
						result.Output = output
						scannerResults[scannerName] = result
						done <- true
					}

				}(scannerName, scanner, scannerResults)
			}

			res := PackagedFamilyResult{
				Result:     scannerResults,
				FamilyName: familyName,
			}

			resChan <- res
			<-done
		}
	}
	close(errChan)
	close(resChan)
}

func defaultTLSConfig(host string) *tls.Config {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	return &tls.Config{ServerName: h, InsecureSkipVerify: true}
}
