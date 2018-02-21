// Copyright 2016 Google Inc. All Rights Reserved.
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

// certcheck is a utility to show and check the contents of certificates.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
)

var (
	root                      = flag.String("root", "", "Root CA certificate file")
	intermediate              = flag.String("intermediate", "", "Intermediate CA certificate file")
	verbose                   = flag.Bool("verbose", false, "Verbose output")
	validate                  = flag.Bool("validate", false, "Validate certificate signatures")
	timecheck                 = flag.Bool("timecheck", false, "Check current validity of certificate")
	revokecheck               = flag.Bool("check_revocation", false, "Check revocation status of certificate")
	ignoreUnknownCriticalExts = flag.Bool("ignore_unknown_critical_exts", false, "Ignore unknown-critical-extension errors")
)

func addCerts(filename string, pool *x509.CertPool) {
	if filename != "" {
		dataList, err := x509util.ReadPossiblePEMFile(filename, "CERTIFICATE")
		if err != nil {
			log.Fatalf("Failed to read certificate file: %v\n", err)
		}
		for _, data := range dataList {
			certs, err := x509.ParseCertificates(data)
			if err != nil {
				log.Fatalf("Failed to parse certificate from %s: %v\n", filename, err)
			}
			for _, cert := range certs {
				pool.AddCert(cert)
			}
		}
	}
}

func main() {
	flag.Parse()

	opts := x509.VerifyOptions{
		KeyUsages:         []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		Roots:             x509.NewCertPool(),
		Intermediates:     x509.NewCertPool(),
		DisableTimeChecks: !*timecheck,
	}
	addCerts(*root, opts.Roots)
	addCerts(*intermediate, opts.Intermediates)

	errcount := 0
	for _, filename := range flag.Args() {
		dataList, err := x509util.ReadPossiblePEMFile(filename, "CERTIFICATE")
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: Failed to read data: %v\n", filename, err)
			errcount++
			continue
		}
		for _, data := range dataList {
			certs, err := x509.ParseCertificates(data)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: %v\n", filename, err.Error())
				errcount++
			}
			for _, cert := range certs {
				if *verbose {
					fmt.Print(x509util.CertificateToString(cert))
				}
				if *ignoreUnknownCriticalExts {
					// We don't want failures from Verify due to unknown critical extensions,
					// so clear them out.
					cert.UnhandledCriticalExtensions = nil
				}
				if *validate {
					_, err := cert.Verify(opts)
					if err != nil {
						fmt.Fprintf(os.Stderr, "%s: Verification error: %v\n", filename, err)
						errcount++
					}
				}
				if *revokecheck {
					if err := checkRevocation(cert); err != nil {
						fmt.Fprintf(os.Stderr, "%s: certificate is revoked: %v\n", filename, err)
						errcount++
					}
				}
			}
		}
	}
	if errcount > 0 {
		os.Exit(1)
	}
}

func checkRevocation(cert *x509.Certificate) error {
	for _, crldp := range cert.CRLDistributionPoints {
		crlDataList, err := x509util.ReadPossiblePEMURL(crldp, "X509 CRL")
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to retrieve CRL from %q: %v\n", crldp, err)
			continue
		}
		for _, crlData := range crlDataList {
			crl, err := x509.ParseCertificateList(crlData)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to parse CRL from %q: %v\n", crldp, err)
				continue
			}
			if *verbose {
				fmt.Printf("\nRevocation data from %s:\n", crldp)
				fmt.Print(x509util.CRLToString(crl))
			}
			for _, c := range crl.TBSCertList.RevokedCertificates {
				if c.SerialNumber.Cmp(cert.SerialNumber) == 0 {
					return fmt.Errorf("certificate is revoked since %v", c.RevocationTime)
				}
			}
		}
	}
	return nil
}
