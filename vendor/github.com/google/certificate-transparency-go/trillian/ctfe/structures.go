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

// Code to handle encoding / decoding various data structures used in RFC 6962. Does not
// contain the low level serialization.

import (
	"crypto"
	"crypto/sha256"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"
)

const millisPerNano int64 = 1000 * 1000

// LogEntry holds the data we send to the backend with the leaf. There is a LogEntry type in
// the CT code but it is a superset of what we need. These structs are purely containers
// for data passed between the frontend and backend. They are not responsible for request
// validation or chain checking. Validation of submitted chains is the responsibility of
// the frontend. The backend handles generic blobs and does not know their format.
type LogEntry struct {
	// The leaf structure that was built from the client submission
	Leaf ct.MerkleTreeLeaf
	// The complete chain for the certificate or precertificate as raw bytes
	Chain []ct.ASN1Cert `tls:"minlen:0,maxlen:16777215"`
}

// GetCTLogID takes the key manager for a log and returns the LogID. (see RFC 6962 S3.2)
// In CT V1 the log id is a hash of the public key.
func GetCTLogID(pk crypto.PublicKey) ([sha256.Size]byte, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(pubBytes), nil
}

// NewLogEntry creates a new LogEntry instance based on the given Merkle tree leaf
// and certificate chain.
func NewLogEntry(leaf ct.MerkleTreeLeaf, certChain []*x509.Certificate) *LogEntry {
	chain := []ct.ASN1Cert{}

	for _, cert := range certChain {
		chain = append(chain, ct.ASN1Cert{Data: cert.Raw})
	}

	return &LogEntry{Leaf: leaf, Chain: chain}
}
