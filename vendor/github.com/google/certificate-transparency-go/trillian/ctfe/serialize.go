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
	"fmt"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/trillian/crypto"
)

// signV1TreeHead signs a tree head for CT. The input STH should have been built from a
// backend response and already checked for validity.
func (c *LogContext) signV1TreeHead(signer *crypto.Signer, sth *ct.SignedTreeHead) error {
	sthBytes, err := ct.SerializeSTHSignatureInput(*sth)
	if err != nil {
		return err
	}
	if sig, ok := c.getLastSTHSignature(sthBytes); ok {
		sth.TreeHeadSignature = sig
		return nil
	}

	signature, err := signer.Sign(sthBytes)
	if err != nil {
		return err
	}

	sth.TreeHeadSignature = ct.DigitallySigned{
		Algorithm: tls.SignatureAndHashAlgorithm{
			Hash: tls.SHA256,
			// This relies on the protobuf enum values matching the TLS-defined values.
			Signature: tls.SignatureAlgorithm(crypto.SignatureAlgorithm(signer.Public())),
		},
		Signature: signature.Signature,
	}
	c.setLastSTHSignature(sthBytes, sth.TreeHeadSignature)
	return nil
}

func buildV1SCT(signer *crypto.Signer, leaf *ct.MerkleTreeLeaf) (*ct.SignedCertificateTimestamp, error) {
	// Serialize SCT signature input to get the bytes that need to be signed
	sctInput := ct.SignedCertificateTimestamp{
		SCTVersion: ct.V1,
		Timestamp:  leaf.TimestampedEntry.Timestamp,
		Extensions: leaf.TimestampedEntry.Extensions,
	}
	data, err := ct.SerializeSCTSignatureInput(sctInput, ct.LogEntry{Leaf: *leaf})
	if err != nil {
		return nil, fmt.Errorf("failed to serialize SCT data: %v", err)
	}

	signature, err := signer.Sign(data)
	if err != nil {
		return nil, fmt.Errorf("failed to sign SCT data: %v", err)
	}

	digitallySigned := ct.DigitallySigned{
		Algorithm: tls.SignatureAndHashAlgorithm{
			Hash: tls.SHA256,
			// This relies on the protobuf enum values matching the TLS-defined values.
			Signature: tls.SignatureAlgorithm(crypto.SignatureAlgorithm(signer.Public())),
		},
		Signature: signature.Signature,
	}

	logID, err := GetCTLogID(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to get logID for signing: %v", err)
	}

	return &ct.SignedCertificateTimestamp{
		SCTVersion: ct.V1,
		LogID:      ct.LogID{KeyID: logID},
		Timestamp:  sctInput.Timestamp,
		Extensions: sctInput.Extensions,
		Signature:  digitallySigned,
	}, nil
}
