package scan

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"text/tabwriter"

	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/scan"
)

var scanUsageText = `cfssl scan -- scan a host for issues
Usage of scan:
        cfssl scan [-family regexp] [-scanner regexp] HOST+
        cfssl scan -list [-family regexp] [-scanner regexp]

Arguments:
        HOST:    Host(s) to scan (including port)
Flags:
`
var scanFlags = []string{"list", "family", "scanner"}

// regexpLoop iterates through each scan Family and Scanner registered in scan.AllFamilies.
// familyFunc is run on each Family with a name matching the family flag's regexp,
// then scannerFunc is run on each Scanner in that Family that matches the scanner flag's regexp
func regexpLoop(familyRegexp, scannerRegexp *regexp.Regexp,
	familyFunc func(*scan.Family),
	scannerFunc func(*scan.Scanner)) {
	for _, family := range scan.AllFamilies {
		if familyRegexp.MatchString(family.Name) {
			familyFunc(family)
			for _, scanner := range family.Scanners {
				if scannerRegexp.MatchString(scanner.Name) {
					scannerFunc(scanner)
				}
			}
		}
	}
}

// indentPrintln prints a multi-line block with the specified indentation.
func indentPrintln(block string, indentLevel int) {
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 4, ' ', 0)
	scanner := bufio.NewScanner(strings.NewReader(block))
	for scanner.Scan() {
		fmt.Fprintf(w, "%s%s\n", strings.Repeat("\t", indentLevel), scanner.Text())
	}
	w.Flush()
}

func scanMain(args []string, c cli.Config) (err error) {
	familyRegexp, err := regexp.Compile(c.Family)
	scannerRegexp, err := regexp.Compile(c.Scanner)
	if err != nil {
		return
	}
	if c.List {
		regexpLoop(
			familyRegexp, scannerRegexp,
			func(f *scan.Family) {
				fmt.Println(f)
			},
			func(s *scan.Scanner) {
				indentPrintln(s.String(), 1)
			},
		)
	} else {
		// Execute for each HOST argument given
		for len(args) > 0 {
			var host string
			host, args, err = cli.PopFirstArgument(args)
			if err != nil {
				return
			}
			// If no port is specified, default to 443
			if _, _, err := net.SplitHostPort(host); err != nil {
				host = net.JoinHostPort(host, "443")
			}
			log.Infof("Scanning %s...", host)
			regexpLoop(
				familyRegexp, scannerRegexp,
				func(f *scan.Family) {
					if log.Level == log.LevelDebug && c.Scanner == "" {
						fmt.Printf("[%s]\n", f.Name)
					}
				},
				func(s *scan.Scanner) {
					grade, output, _ := s.Scan(host)
					fmt.Printf("%s: %s\n", s.Name, grade)
					if log.Level == log.LevelDebug && output != nil {
						indentPrintln(output.String(), 1)
					}
				},
			)
		}
	}
	return
}

// Command assembles the definition of Command 'scan'
var Command = &cli.Command{UsageText: scanUsageText, Flags: scanFlags, Main: scanMain}
