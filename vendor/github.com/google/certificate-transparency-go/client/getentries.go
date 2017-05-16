package client

import (
	"errors"
	"fmt"
	"strconv"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"golang.org/x/net/context"
)

// GetRawEntries exposes the /ct/v1/get-entries result with only the JSON parsing done.
func (c *LogClient) GetRawEntries(ctx context.Context, start, end int64) (*ct.GetEntriesResponse, error) {
	if end < 0 {
		return nil, errors.New("end should be >= 0")
	}
	if end < start {
		return nil, errors.New("start should be <= end")
	}

	params := map[string]string{
		"start": strconv.FormatInt(start, 10),
		"end":   strconv.FormatInt(end, 10),
	}
	if ctx == nil {
		ctx = context.TODO()
	}

	var resp ct.GetEntriesResponse
	_, err := c.GetAndParse(ctx, ct.GetEntriesPath, params, &resp)
	if err != nil {
		return nil, err
	}

	return &resp, nil
}

// GetEntries attempts to retrieve the entries in the sequence [|start|, |end|] from the CT log server. (see section 4.6.)
// Returns a slice of LeafInputs or a non-nil error.
func (c *LogClient) GetEntries(ctx context.Context, start, end int64) ([]ct.LogEntry, error) {
	resp, err := c.GetRawEntries(ctx, start, end)
	if err != nil {
		return nil, err
	}
	entries := make([]ct.LogEntry, len(resp.Entries))
	for index, entry := range resp.Entries {
		var leaf ct.MerkleTreeLeaf
		if rest, err := tls.Unmarshal(entry.LeafInput, &leaf); err != nil {
			return nil, fmt.Errorf("failed to unmarshal MerkleTreeLeaf: %v", err)
		} else if len(rest) > 0 {
			return nil, fmt.Errorf("trailing data (%d bytes) after MerkleTreeLeaf", len(rest))
		}
		entries[index].Leaf = leaf

		var chain []ct.ASN1Cert
		switch leaf.TimestampedEntry.EntryType {
		case ct.X509LogEntryType:
			var certChain ct.CertificateChain
			if rest, err := tls.Unmarshal(entry.ExtraData, &certChain); err != nil {
				return nil, fmt.Errorf("failed to unmarshal ExtraData for index %d: %v", index, err)
			} else if len(rest) > 0 {
				return nil, fmt.Errorf("trailing data (%d bytes) after CertificateChain for index %d", len(rest), index)
			}
			chain = certChain.Entries

		case ct.PrecertLogEntryType:
			var precertChain ct.PrecertChainEntry
			if rest, err := tls.Unmarshal(entry.ExtraData, &precertChain); err != nil {
				return nil, fmt.Errorf("failed to unmarshal PrecertChainEntry: %v", err)
			} else if len(rest) > 0 {
				return nil, fmt.Errorf("trailing data (%d bytes) after PrecertChainEntry for index %d", len(rest), index)
			}
			chain = append(chain, precertChain.PreCertificate)
			chain = append(chain, precertChain.CertificateChain...)

		default:
			return nil, fmt.Errorf("saw unknown entry type: %v", leaf.TimestampedEntry.EntryType)
		}
		entries[index].Chain = chain
		entries[index].Index = start + int64(index)
	}
	return entries, nil
}
