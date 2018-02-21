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

package ctfe

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/x509"
)

// OID of the non-critical extension used to mark pre-certificates, defined in RFC 6962
var ctPoisonExtensionOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}

// Byte representation of ASN.1 NULL.
var asn1NullBytes = []byte{0x05, 0x00}

// IsPrecertificate tests if a certificate is a pre-certificate as defined in CT.
// An error is returned if the CT extension is present but is not ASN.1 NULL as defined
// by the spec.
func IsPrecertificate(cert *x509.Certificate) (bool, error) {
	for _, ext := range cert.Extensions {
		if ctPoisonExtensionOID.Equal(ext.Id) {
			if !ext.Critical || !bytes.Equal(asn1NullBytes, ext.Value) {
				return false, fmt.Errorf("CT poison ext is not critical or invalid: %v", ext)
			}

			return true, nil
		}
	}

	return false, nil
}

// ValidateChain takes the certificate chain as it was parsed from a JSON request. Ensures all
// elements in the chain decode as X.509 certificates. Ensures that there is a valid path from the
// end entity certificate in the chain to a trusted root cert, possibly using the intermediates
// supplied in the chain. Then applies the RFC requirement that the path must involve all
// the submitted chain in the order of submission.
func ValidateChain(rawChain [][]byte, validationOpts CertValidationOpts) ([]*x509.Certificate, error) {
	// First make sure the certs parse as X.509
	chain := make([]*x509.Certificate, 0, len(rawChain))
	intermediatePool := NewPEMCertPool()

	for i, certBytes := range rawChain {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			_, ok := err.(x509.NonFatalErrors)
			if !ok {
				return nil, err
			}
		}

		chain = append(chain, cert)

		// All but the first cert form part of the intermediate pool
		if i > 0 {
			intermediatePool.AddCert(cert)
		}
	}

	naStart := validationOpts.notAfterStart
	naLimit := validationOpts.notAfterLimit

	// Check whether the expiry date of this certificate is within the acceptable
	// range.
	if naStart != nil && chain[0].NotAfter.Before(*naStart) {
		return nil, fmt.Errorf("certificate NotAfter (%v) < %v", chain[0].NotAfter, *naStart)
	}
	if naLimit != nil && !chain[0].NotAfter.Before(*naLimit) {
		return nil, fmt.Errorf("certificate NotAfter (%v) >= %v", chain[0].NotAfter, *naLimit)
	}

	if validationOpts.acceptOnlyCA && !chain[0].IsCA {
		return nil, errors.New("only certificates with CA bit set are accepted")
	}

	// We can now do the verification
	verifyOpts := x509.VerifyOptions{
		Roots:             validationOpts.trustedRoots.CertPool(),
		Intermediates:     intermediatePool.CertPool(),
		DisableTimeChecks: !validationOpts.rejectExpired,
		KeyUsages:         validationOpts.extKeyUsages,
	}

	// We don't want failures from Verify due to unknown critical extensions in the leaf,
	// so clear them out.
	chain[0].UnhandledCriticalExtensions = nil

	for i := 1; i < len(chain); i++ {
		// The PolicyConstraints extension is required to be marked critical
		// (RFC 5280 s4.2.1.11), but is not parsed by the Go x509 library.
		// To allow validation of chains where an intermediate has this extension,
		// remove it from the unknown critical extensions slice.
		for j, extOID := range chain[i].UnhandledCriticalExtensions {
			if extOID.Equal(x509.OIDExtensionPolicyConstraints) {
				chain[i].UnhandledCriticalExtensions = append(chain[i].UnhandledCriticalExtensions[:j], chain[i].UnhandledCriticalExtensions[j+1:]...)
				break
			}
		}
	}

	chains, err := chain[0].Verify(verifyOpts)
	if err != nil {
		return nil, err
	}

	if len(chains) == 0 {
		return nil, errors.New("no path to root found when trying to validate chains")
	}

	// Verify might have found multiple paths to roots. Now we check that we have a path that
	// uses all the certs in the order they were submitted so as to comply with RFC 6962
	// requirements detailed in Section 3.1.
	for _, verifiedChain := range chains {
		if chainsEquivalent(chain, verifiedChain) {
			return verifiedChain, nil
		}
	}

	return nil, errors.New("no RFC compliant path to root found when trying to validate chain")
}

func chainsEquivalent(inChain []*x509.Certificate, verifiedChain []*x509.Certificate) bool {
	// The verified chain includes a root, but the input chain may or may not include a
	// root (RFC 6962 s4.1/ s4.2 "the last [certificate] is either the root certificate
	// or a certificate that chains to a known root certificate").
	if len(inChain) != len(verifiedChain) && len(inChain) != (len(verifiedChain)-1) {
		return false
	}

	for i, certInChain := range inChain {
		if !certInChain.Equal(verifiedChain[i]) {
			return false
		}
	}
	return true
}
