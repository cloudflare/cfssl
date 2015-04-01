package scan

import (
	"fmt"
	"net"
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
	// Legacy describes a host with non-ideal configuration that maintains support for legacy clients.
	Legacy
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
	case Legacy:
		return "Legacy"
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
	// Name provides a short name for the Scanner.
	Name string
	// Description describes the nature of the scan to be performed.
	Description string
	// scan is the function that scans the given host and provides a Grade and Output.
	scan func(host string) (Grade, Output, error)
}

// Scan performs the scan to be performed on the given host and stores its result.
func (s *Scanner) Scan(host string) (Grade, Output, error) {
	grade, output, err := s.scan(host)
	if err != nil {
		log.Infof("%s: %s", s.Name, err)
		return grade, output, err
	}
	return grade, output, err
}

// String gives the name of the Scanner, and its description if loglevel is 0.
func (s *Scanner) String() string {
	ret := fmt.Sprintf("%s", s.Name)
	if log.Level == log.LevelDebug {
		ret += fmt.Sprintf(": %s", s.Description)
	}
	return ret
}

func defaultTLSConfig(host string) *tls.Config {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	return &tls.Config{ServerName: h, InsecureSkipVerify: true}
}

// Family defines a set of related scans meant to be run together in sequence.
type Family struct {
	// Name is a short name for the Family.
	Name string
	// Description gives a short description of the scans performed scan/scan_common.goon the host.
	Description string
	// Scanners is a list of scanners that are to be run in sequence.
	Scanners []*Scanner
}

// String gives the name of the Family, and its description if loglevel is 0.
func (f *Family) String() string {
	ret := fmt.Sprintf("%s", f.Name)
	if log.Level == 0 {
		ret += fmt.Sprintf(": %s", f.Description)
	}
	return ret
}

// AllFamilies contains each scan Family that is defined
var AllFamilies = []*Family{
	Connectivity,
	TLSHandshake,
	TLSSession,
	PKI,
}
