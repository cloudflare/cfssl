// Package client is a CT log client implementation and contains types and code
// for interacting with RFC6962-compliant CT Log instances.
// See http://tools.ietf.org/html/rfc6962 for details
package client

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	ct "github.com/google/certificate-transparency/go"
	"github.com/google/certificate-transparency/go/jsonclient"
	"golang.org/x/net/context"
)

// URI paths for CT Log endpoints
const (
	AddChainPath          = "/ct/v1/add-chain"
	AddPreChainPath       = "/ct/v1/add-pre-chain"
	AddJSONPath           = "/ct/v1/add-json"
	GetSTHPath            = "/ct/v1/get-sth"
	GetEntriesPath        = "/ct/v1/get-entries"
	GetProofByHashPath    = "/ct/v1/get-proof-by-hash"
	GetSTHConsistencyPath = "/ct/v1/get-sth-consistency"
	GetRootsPath          = "/ct/v1/get-roots"
)

// LogClient represents a client for a given CT Log instance
type LogClient struct {
	jsonclient.JSONClient
}

//////////////////////////////////////////////////////////////////////////////////
// JSON structures follow.
// These represent the structures returned by the CT Log server.
//////////////////////////////////////////////////////////////////////////////////

// addChainRequest represents the JSON request body sent to the add-chain CT
// method.
type addChainRequest struct {
	Chain [][]byte `json:"chain"`
}

// addChainResponse represents the JSON response to the add-chain CT method.
// An SCT represents a Log's promise to integrate a [pre-]certificate into the
// log within a defined period of time.
type addChainResponse struct {
	SCTVersion ct.Version `json:"sct_version"` // SCT structure version
	ID         []byte     `json:"id"`          // Log ID
	Timestamp  uint64     `json:"timestamp"`   // Timestamp of issuance
	Extensions string     `json:"extensions"`  // Holder for any CT extensions
	Signature  []byte     `json:"signature"`   // Log signature for this SCT
}

// addJSONRequest represents the JSON request body sent to the add-json CT
// method.
type addJSONRequest struct {
	Data interface{} `json:"data"`
}

// getSTHResponse respresents the JSON response to the get-sth CT method
type getSTHResponse struct {
	TreeSize          uint64 `json:"tree_size"`           // Number of certs in the current tree
	Timestamp         uint64 `json:"timestamp"`           // Time that the tree was created
	SHA256RootHash    []byte `json:"sha256_root_hash"`    // Root hash of the tree
	TreeHeadSignature []byte `json:"tree_head_signature"` // Log signature for this STH
}

// getConsistencyProofResponse represents the JSON response to the get-consistency-proof CT method
type getConsistencyProofResponse struct {
	Consistency [][]byte `json:"consistency"`
}

// getAuditProofResponse represents the JSON response to the CT get-audit-proof method
type getAuditProofResponse struct {
	Hash     []string `json:"hash"`      // the hashes which make up the proof
	TreeSize uint64   `json:"tree_size"` // the tree size against which this proof is constructed
}

// getAcceptedRootsResponse represents the JSON response to the CT get-roots method.
type getAcceptedRootsResponse struct {
	Certificates []string `json:"certificates"`
}

// getEntryAndProofReponse represents the JSON response to the CT get-entry-and-proof method
type getEntryAndProofResponse struct {
	LeafInput string   `json:"leaf_input"` // the entry itself
	ExtraData string   `json:"extra_data"` // any chain provided when the entry was added to the log
	AuditPath []string `json:"audit_path"` // the corresponding proof
}

// GetProofByHashResponse represents the JSON response to the CT get-proof-by-hash method.
type GetProofByHashResponse struct {
	LeafIndex int64    `json:"leaf_index"` // The 0-based index of the end entity corresponding to the "hash" parameter.
	AuditPath [][]byte `json:"audit_path"` // An array of base64-encoded Merkle Tree nodes proving the inclusion of the chosen certificate.
}

// New constructs a new LogClient instance.
// |uri| is the base URI of the CT log instance to interact with, e.g.
// http://ct.googleapis.com/pilot
// |hc| is the underlying client to be used for HTTP requests to the CT log.
// |opts| can be used to provide a customer logger interface and a public key
// for signature verification.
func New(uri string, hc *http.Client, opts jsonclient.Options) (*LogClient, error) {
	logClient, err := jsonclient.New(uri, hc, opts)
	if err != nil {
		return nil, err
	}
	return &LogClient{*logClient}, err
}

// Attempts to add |chain| to the log, using the api end-point specified by
// |path|. If provided context expires before submission is complete an
// error will be returned.
func (c *LogClient) addChainWithRetry(ctx context.Context, ctype ct.LogEntryType, path string, chain []ct.ASN1Cert) (*ct.SignedCertificateTimestamp, error) {
	var resp addChainResponse
	var req addChainRequest
	for _, link := range chain {
		req.Chain = append(req.Chain, link)
	}

	_, err := c.PostAndParseWithRetry(ctx, path, &req, &resp)
	if err != nil {
		return nil, err
	}

	ds, err := ct.UnmarshalDigitallySigned(bytes.NewReader(resp.Signature))
	if err != nil {
		return nil, err
	}

	var logID ct.SHA256Hash
	copy(logID[:], resp.ID)
	sct := &ct.SignedCertificateTimestamp{
		SCTVersion: resp.SCTVersion,
		LogID:      logID,
		Timestamp:  resp.Timestamp,
		Extensions: ct.CTExtensions(resp.Extensions),
		Signature:  *ds}
	err = c.VerifySCTSignature(*sct, ctype, chain)
	if err != nil {
		return nil, err
	}
	return sct, nil
}

// AddChain adds the (DER represented) X509 |chain| to the log.
func (c *LogClient) AddChain(ctx context.Context, chain []ct.ASN1Cert) (*ct.SignedCertificateTimestamp, error) {
	return c.addChainWithRetry(ctx, ct.X509LogEntryType, AddChainPath, chain)
}

// AddPreChain adds the (DER represented) Precertificate |chain| to the log.
func (c *LogClient) AddPreChain(ctx context.Context, chain []ct.ASN1Cert) (*ct.SignedCertificateTimestamp, error) {
	return c.addChainWithRetry(ctx, ct.PrecertLogEntryType, AddPreChainPath, chain)
}

// AddJSON submits arbitrary data to to XJSON server.
func (c *LogClient) AddJSON(ctx context.Context, data interface{}) (*ct.SignedCertificateTimestamp, error) {
	req := addJSONRequest{
		Data: data,
	}
	var resp addChainResponse
	_, err := c.PostAndParse(ctx, AddJSONPath, &req, &resp)
	if err != nil {
		return nil, err
	}
	ds, err := ct.UnmarshalDigitallySigned(bytes.NewReader(resp.Signature))
	if err != nil {
		return nil, err
	}
	var logID ct.SHA256Hash
	copy(logID[:], resp.ID)
	return &ct.SignedCertificateTimestamp{
		SCTVersion: resp.SCTVersion,
		LogID:      logID,
		Timestamp:  resp.Timestamp,
		Extensions: ct.CTExtensions(resp.Extensions),
		Signature:  *ds}, nil
}

// GetSTH retrieves the current STH from the log.
// Returns a populated SignedTreeHead, or a non-nil error.
func (c *LogClient) GetSTH(ctx context.Context) (sth *ct.SignedTreeHead, err error) {
	var resp getSTHResponse
	_, err = c.GetAndParse(ctx, GetSTHPath, nil, &resp)
	if err != nil {
		return
	}
	sth = &ct.SignedTreeHead{
		TreeSize:  resp.TreeSize,
		Timestamp: resp.Timestamp,
	}

	if len(resp.SHA256RootHash) != sha256.Size {
		return nil, fmt.Errorf("sha256_root_hash is invalid length, expected %d got %d", sha256.Size, len(resp.SHA256RootHash))
	}
	copy(sth.SHA256RootHash[:], resp.SHA256RootHash)

	ds, err := ct.UnmarshalDigitallySigned(bytes.NewReader(resp.TreeHeadSignature))
	if err != nil {
		return nil, err
	}
	sth.TreeHeadSignature = *ds
	err = c.VerifySTHSignature(*sth)
	if err != nil {
		return nil, err
	}
	return
}

// VerifySTHSignature checks the signature in sth, returning any error encountered or nil if verification is
// successful.
func (c *LogClient) VerifySTHSignature(sth ct.SignedTreeHead) error {
	if c.Verifier == nil {
		// Can't verify signatures without a verifier
		return nil
	}
	return c.Verifier.VerifySTHSignature(sth)
}

// VerifySCTSignature checks the signature in sct for the given LogEntryType, with associated certificate chain.
func (c *LogClient) VerifySCTSignature(sct ct.SignedCertificateTimestamp, ctype ct.LogEntryType, certData []ct.ASN1Cert) error {
	if c.Verifier == nil {
		// Can't verify signatures without a verifier
		return nil
	}

	if ctype == ct.PrecertLogEntryType {
		// TODO(drysdale): cope with pre-certs, which need to have the
		// following fields set:
		//    leaf.PrecertEntry.TBSCertificate
		//    leaf.PrecertEntry.IssuerKeyHash  (SHA-256 of issuer's public key)
		return errors.New("SCT verification for pre-certificates unimplemented")
	}
	// Build enough of a Merkle tree leaf for the verifier to work on.
	leaf := ct.MerkleTreeLeaf{
		Version:  sct.SCTVersion,
		LeafType: ct.TimestampedEntryLeafType,
		TimestampedEntry: ct.TimestampedEntry{
			Timestamp:  sct.Timestamp,
			EntryType:  ctype,
			X509Entry:  certData[0],
			Extensions: sct.Extensions}}
	entry := ct.LogEntry{Leaf: leaf}
	return c.Verifier.VerifySCTSignature(sct, entry)
}

// GetSTHConsistency retrieves the consistency proof between two snapshots.
func (c *LogClient) GetSTHConsistency(ctx context.Context, first, second uint64) ([][]byte, error) {
	base10 := 10
	params := map[string]string{
		"first":  strconv.FormatUint(first, base10),
		"second": strconv.FormatUint(second, base10),
	}
	var resp getConsistencyProofResponse
	if _, err := c.GetAndParse(ctx, GetSTHConsistencyPath, params, &resp); err != nil {
		return nil, err
	}
	return resp.Consistency, nil
}

// GetProofByHash returns an audit path for the hash of an SCT.
func (c *LogClient) GetProofByHash(ctx context.Context, hash []byte, treeSize uint64) (*GetProofByHashResponse, error) {
	b64Hash := url.QueryEscape(base64.StdEncoding.EncodeToString(hash))
	base10 := 10
	params := map[string]string{
		"tree_size": strconv.FormatUint(treeSize, base10),
		"hash":      b64Hash,
	}
	var resp GetProofByHashResponse
	if _, err := c.GetAndParse(ctx, GetProofByHashPath, params, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetAcceptedRoots retrieves the set of acceptable root certificates for a log.
func (c *LogClient) GetAcceptedRoots(ctx context.Context) ([]ct.ASN1Cert, error) {
	var resp getAcceptedRootsResponse
	if _, err := c.GetAndParse(ctx, GetRootsPath, nil, &resp); err != nil {
		return nil, err
	}
	var roots []ct.ASN1Cert
	for _, cert64 := range resp.Certificates {
		cert, err := base64.StdEncoding.DecodeString(cert64)
		if err != nil {
			return nil, err
		}
		roots = append(roots, cert)
	}
	return roots, nil
}
