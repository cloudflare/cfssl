package ct

import (
	"crypto"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/certificate-transparency-go/tls"
)

// SerializeSCTSignatureInput serializes the passed in sct and log entry into
// the correct format for signing.
func SerializeSCTSignatureInput(sct SignedCertificateTimestamp, entry LogEntry) ([]byte, error) {
	switch sct.SCTVersion {
	case V1:
		input := CertificateTimestamp{
			SCTVersion:    sct.SCTVersion,
			SignatureType: CertificateTimestampSignatureType,
			Timestamp:     sct.Timestamp,
			EntryType:     entry.Leaf.TimestampedEntry.EntryType,
			Extensions:    sct.Extensions,
		}
		switch entry.Leaf.TimestampedEntry.EntryType {
		case X509LogEntryType:
			input.X509Entry = entry.Leaf.TimestampedEntry.X509Entry
		case PrecertLogEntryType:
			input.PrecertEntry = &PreCert{
				IssuerKeyHash:  entry.Leaf.TimestampedEntry.PrecertEntry.IssuerKeyHash,
				TBSCertificate: entry.Leaf.TimestampedEntry.PrecertEntry.TBSCertificate,
			}
		case XJSONLogEntryType:
			input.JSONEntry = entry.Leaf.TimestampedEntry.JSONEntry
		default:
			return nil, fmt.Errorf("unsupported entry type %s", entry.Leaf.TimestampedEntry.EntryType)
		}
		return tls.Marshal(input)
	default:
		return nil, fmt.Errorf("unknown SCT version %d", sct.SCTVersion)
	}
}

// SerializeSTHSignatureInput serializes the passed in STH into the correct
// format for signing.
func SerializeSTHSignatureInput(sth SignedTreeHead) ([]byte, error) {
	switch sth.Version {
	case V1:
		if len(sth.SHA256RootHash) != crypto.SHA256.Size() {
			return nil, fmt.Errorf("invalid TreeHash length, got %d expected %d", len(sth.SHA256RootHash), crypto.SHA256.Size())
		}

		input := TreeHeadSignature{
			Version:        sth.Version,
			SignatureType:  TreeHashSignatureType,
			Timestamp:      sth.Timestamp,
			TreeSize:       sth.TreeSize,
			SHA256RootHash: sth.SHA256RootHash,
		}
		return tls.Marshal(input)
	default:
		return nil, fmt.Errorf("unsupported STH version %d", sth.Version)
	}
}

// CreateX509MerkleTreeLeaf generates a MerkleTreeLeaf for an X509 cert
func CreateX509MerkleTreeLeaf(cert ASN1Cert, timestamp uint64) *MerkleTreeLeaf {
	return &MerkleTreeLeaf{
		Version:  V1,
		LeafType: TimestampedEntryLeafType,
		TimestampedEntry: &TimestampedEntry{
			Timestamp: timestamp,
			EntryType: X509LogEntryType,
			X509Entry: &cert,
		},
	}
}

// CreateJSONMerkleTreeLeaf creates the merkle tree leaf for json data.
func CreateJSONMerkleTreeLeaf(data interface{}, timestamp uint64) *MerkleTreeLeaf {
	jsonData, err := json.Marshal(AddJSONRequest{Data: data})
	if err != nil {
		return nil
	}
	// Match the JSON serialization implemented by json-c
	jsonStr := strings.Replace(string(jsonData), ":", ": ", -1)
	jsonStr = strings.Replace(jsonStr, ",", ", ", -1)
	jsonStr = strings.Replace(jsonStr, "{", "{ ", -1)
	jsonStr = strings.Replace(jsonStr, "}", " }", -1)
	jsonStr = strings.Replace(jsonStr, "/", `\/`, -1)
	// TODO: Pending google/certificate-transparency#1243, replace with
	// ObjectHash once supported by CT server.

	return &MerkleTreeLeaf{
		Version:  V1,
		LeafType: TimestampedEntryLeafType,
		TimestampedEntry: &TimestampedEntry{
			Timestamp: timestamp,
			EntryType: XJSONLogEntryType,
			JSONEntry: &JSONDataEntry{Data: []byte(jsonStr)},
		},
	}
}
