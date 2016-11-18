package client

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"

	ct "github.com/google/certificate-transparency/go"
	"golang.org/x/net/context"
)

// LeafEntry respresents a JSON leaf entry.
type LeafEntry struct {
	LeafInput []byte `json:"leaf_input"`
	ExtraData []byte `json:"extra_data"`
}

// GetEntriesResponse respresents the JSON response to the CT get-entries method.
type GetEntriesResponse struct {
	Entries []LeafEntry `json:"entries"` // the list of returned entries
}

// GetRawEntries exposes the /ct/v1/get-entries result with only the JSON parsing done.
func (c *LogClient) GetRawEntries(ctx context.Context, start, end int64) (*GetEntriesResponse, error) {
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

	var resp GetEntriesResponse
	_, err := c.GetAndParse(ctx, GetEntriesPath, params, &resp)
	if err != nil {
		return nil, err
	}

	return &resp, nil
}

// GetEntries attempts to retrieve the entries in the sequence [|start|, |end|] from the CT log server. (see section 4.6.)
// Returns a slice of LeafInputs or a non-nil error.
func (c *LogClient) GetEntries(start, end int64) ([]ct.LogEntry, error) {
	resp, err := c.GetRawEntries(context.TODO(), start, end)
	if err != nil {
		return nil, err
	}
	entries := make([]ct.LogEntry, len(resp.Entries))
	for index, entry := range resp.Entries {
		leaf, err := ct.ReadMerkleTreeLeaf(bytes.NewBuffer(entry.LeafInput))
		if err != nil {
			return nil, err
		}
		entries[index].Leaf = *leaf

		var chain []ct.ASN1Cert
		switch leaf.TimestampedEntry.EntryType {
		case ct.X509LogEntryType:
			chain, err = ct.UnmarshalX509ChainArray(entry.ExtraData)

		case ct.PrecertLogEntryType:
			chain, err = ct.UnmarshalPrecertChainArray(entry.ExtraData)

		default:
			return nil, fmt.Errorf("saw unknown entry type: %v", leaf.TimestampedEntry.EntryType)
		}
		if err != nil {
			return nil, err
		}
		entries[index].Chain = chain
		entries[index].Index = start + int64(index)
	}
	return entries, nil
}
