// Copyright 2014 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"path"
	"regexp"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/scanner"
)

const (
	// matchesNothingRegex is a regex which cannot match any input.
	matchesNothingRegex = "a^"
)

var logURI = flag.String("log_uri", "http://ct.googleapis.com/aviator", "CT log base URI")
var matchSubjectRegex = flag.String("match_subject_regex", ".*", "Regex to match CN/SAN")
var matchIssuerRegex = flag.String("match_issuer_regex", "", "Regex to match in issuer CN")
var precertsOnly = flag.Bool("precerts_only", false, "Only match precerts")
var serialNumber = flag.String("serial_number", "", "Serial number of certificate of interest")
var parseErrors = flag.Bool("parse_errors", false, "Only match certificates with parse errors")
var nfParseErrors = flag.Bool("non_fatal_errors", false, "Treat non-fatal parse errors as also matching (with --parse_errors)")
var validateErrors = flag.Bool("validate_errors", false, "Only match certificates with validation errors")
var batchSize = flag.Int("batch_size", 1000, "Max number of entries to request at per call to get-entries")
var numWorkers = flag.Int("num_workers", 2, "Number of concurrent matchers")
var parallelFetch = flag.Int("parallel_fetch", 2, "Number of concurrent GetEntries fetches")
var startIndex = flag.Int64("start_index", 0, "Log index to start scanning at")
var quiet = flag.Bool("quiet", false, "Don't print out extra logging messages, only matches.")
var printChains = flag.Bool("print_chains", false, "If true prints the whole chain rather than a summary")
var dumpDir = flag.String("dump_dir", "", "Directory to store matched certificates in")

func dumpData(entry *ct.LogEntry) {
	if *dumpDir == "" {
		return
	}
	chainFrom := 0
	prefix := "unknown"
	if entry.Leaf.TimestampedEntry.EntryType == ct.X509LogEntryType {
		prefix = "cert"
		name := fmt.Sprintf("%s-%014d-leaf.der", prefix, entry.Index)
		filename := path.Join(*dumpDir, name)
		err := ioutil.WriteFile(filename, entry.Leaf.TimestampedEntry.X509Entry.Data, 0644)
		if err != nil {
			log.Printf("Failed to dump data for %s at index %d: %v", prefix, entry.Index, err)
		}
	} else if entry.Leaf.TimestampedEntry.EntryType == ct.PrecertLogEntryType {
		prefix = "pecert"
		// For a pre-certificate the TimestampedEntry only holds the TBSCertificate, but
		// the Chain data has the full pre-certificate as the first entry.
		name := fmt.Sprintf("%s-%014d-precert.der", prefix, entry.Index)
		filename := path.Join(*dumpDir, name)
		if len(entry.Chain) == 0 {
			log.Printf("Precert entry missing chain[0] at index %d", entry.Index)
			return
		}
		if err := ioutil.WriteFile(filename, entry.Chain[0].Data, 0644); err != nil {
			log.Printf("Failed to dump data for %s at index %d: %v", prefix, entry.Index, err)
		}
		chainFrom = 1
	} else {
		log.Printf("Unknown log entry type %d", entry.Leaf.TimestampedEntry.EntryType)
	}
	for ii := chainFrom; ii < len(entry.Chain); ii++ {
		name := fmt.Sprintf("%s-%014d-%02d.der", prefix, entry.Index, ii)
		filename := path.Join(*dumpDir, name)
		err := ioutil.WriteFile(filename, entry.Chain[ii].Data, 0644)
		if err != nil {
			log.Printf("Failed to dump data for CA at index %d: %v", entry.Index, err)
		}
	}
}

// Prints out a short bit of info about |cert|, found at |index| in the
// specified log
func logCertInfo(entry *ct.LogEntry) {
	if entry.X509Cert != nil {
		log.Printf("Process cert at index %d: CN: '%s'", entry.Index, entry.X509Cert.Subject.CommonName)
		dumpData(entry)
	} else {
		log.Printf("Process cert at index %d: <unparsed>", entry.Index)
	}
}

// Prints out a short bit of info about |precert|, found at |index| in the
// specified log
func logPrecertInfo(entry *ct.LogEntry) {
	if entry.Precert != nil {
		log.Printf("Process precert at index %d: CN: '%s' Issuer: %s", entry.Index,
			entry.Precert.TBSCertificate.Subject.CommonName, entry.Precert.TBSCertificate.Issuer.CommonName)
		dumpData(entry)
	} else {
		log.Printf("Process precert at index %d: <unparsed>", entry.Index)
	}
}

func chainToString(certs []ct.ASN1Cert) string {
	var output []byte

	for _, cert := range certs {
		output = append(output, cert.Data...)
	}

	return base64.StdEncoding.EncodeToString(output)
}

func logFullChain(entry *ct.LogEntry) {
	log.Printf("Index %d: Chain: %s", entry.Index, chainToString(entry.Chain))
}

func createRegexes(regexValue string) (*regexp.Regexp, *regexp.Regexp) {
	// Make a regex matcher
	var certRegex *regexp.Regexp
	precertRegex := regexp.MustCompile(regexValue)
	switch *precertsOnly {
	case true:
		certRegex = regexp.MustCompile(matchesNothingRegex)
	case false:
		certRegex = precertRegex
	}

	return certRegex, precertRegex
}

func createMatcherFromFlags(logClient *client.LogClient) (interface{}, error) {
	if *parseErrors {
		return scanner.CertParseFailMatcher{MatchNonFatalErrs: *nfParseErrors}, nil
	}
	if *validateErrors {
		matcher := scanner.CertVerifyFailMatcher{}
		matcher.PopulateRoots(context.TODO(), logClient)
		return matcher, nil
	}
	if *matchIssuerRegex != "" {
		certRegex, precertRegex := createRegexes(*matchIssuerRegex)
		return scanner.MatchIssuerRegex{
			CertificateIssuerRegex:    certRegex,
			PrecertificateIssuerRegex: precertRegex}, nil
	}
	if *serialNumber != "" {
		log.Printf("Using SerialNumber matcher on %s", *serialNumber)
		var sn big.Int
		_, success := sn.SetString(*serialNumber, 0)
		if !success {
			return nil, fmt.Errorf("Invalid serialNumber %s", *serialNumber)
		}
		return scanner.MatchSerialNumber{SerialNumber: sn}, nil
	}
	certRegex, precertRegex := createRegexes(*matchSubjectRegex)
	return scanner.MatchSubjectRegex{
		CertificateSubjectRegex:    certRegex,
		PrecertificateSubjectRegex: precertRegex}, nil
}

func main() {
	flag.Parse()
	logClient, err := client.New(*logURI, &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   10,
			DisableKeepAlives:     false,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}, jsonclient.Options{})
	if err != nil {
		log.Fatal(err)
	}
	matcher, err := createMatcherFromFlags(logClient)
	if err != nil {
		log.Fatal(err)
	}

	opts := scanner.ScannerOptions{
		Matcher:       matcher,
		BatchSize:     *batchSize,
		NumWorkers:    *numWorkers,
		ParallelFetch: *parallelFetch,
		StartIndex:    *startIndex,
		Quiet:         *quiet,
	}
	scanner := scanner.NewScanner(logClient, opts)

	ctx := context.Background()
	if *printChains {
		scanner.Scan(ctx, logFullChain, logFullChain)
	} else {
		scanner.Scan(ctx, logCertInfo, logPrecertInfo)
	}
}
