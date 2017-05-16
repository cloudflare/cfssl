// Package client is a CT log client implementation and contains types and code
// for interacting with RFC6962-compliant CT Log instances.
// See http://tools.ietf.org/html/rfc6962 for details
package client

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
	"golang.org/x/net/context"
)

// LogClient represents a client for a given CT Log instance
type LogClient struct {
	jsonclient.JSONClient
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
	var resp ct.AddChainResponse
	var req ct.AddChainRequest
	for _, link := range chain {
		req.Chain = append(req.Chain, link.Data)
	}

	_, err := c.PostAndParseWithRetry(ctx, path, &req, &resp)
	if err != nil {
		return nil, err
	}

	var ds ct.DigitallySigned
	if rest, err := tls.Unmarshal(resp.Signature, &ds); err != nil {
		return nil, err
	} else if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data (%d bytes) after DigitallySigned", len(rest))
	}

	var logID ct.LogID
	copy(logID.KeyID[:], resp.ID)
	sct := &ct.SignedCertificateTimestamp{
		SCTVersion: resp.SCTVersion,
		LogID:      logID,
		Timestamp:  resp.Timestamp,
		Extensions: ct.CTExtensions(resp.Extensions),
		Signature:  ds,
	}
	err = c.VerifySCTSignature(*sct, ctype, chain)
	if err != nil {
		return nil, err
	}
	return sct, nil
}

// AddChain adds the (DER represented) X509 |chain| to the log.
func (c *LogClient) AddChain(ctx context.Context, chain []ct.ASN1Cert) (*ct.SignedCertificateTimestamp, error) {
	return c.addChainWithRetry(ctx, ct.X509LogEntryType, ct.AddChainPath, chain)
}

// AddPreChain adds the (DER represented) Precertificate |chain| to the log.
func (c *LogClient) AddPreChain(ctx context.Context, chain []ct.ASN1Cert) (*ct.SignedCertificateTimestamp, error) {
	return c.addChainWithRetry(ctx, ct.PrecertLogEntryType, ct.AddPreChainPath, chain)
}

// AddJSON submits arbitrary data to to XJSON server.
func (c *LogClient) AddJSON(ctx context.Context, data interface{}) (*ct.SignedCertificateTimestamp, error) {
	req := ct.AddJSONRequest{Data: data}
	var resp ct.AddChainResponse
	_, err := c.PostAndParse(ctx, ct.AddJSONPath, &req, &resp)
	if err != nil {
		return nil, err
	}
	var ds ct.DigitallySigned
	if rest, err := tls.Unmarshal(resp.Signature, &ds); err != nil {
		return nil, err
	} else if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data (%d bytes) after DigitallySigned", len(rest))
	}
	var logID ct.LogID
	copy(logID.KeyID[:], resp.ID)
	return &ct.SignedCertificateTimestamp{
		SCTVersion: resp.SCTVersion,
		LogID:      logID,
		Timestamp:  resp.Timestamp,
		Extensions: ct.CTExtensions(resp.Extensions),
		Signature:  ds,
	}, nil
}

// GetSTH retrieves the current STH from the log.
// Returns a populated SignedTreeHead, or a non-nil error.
func (c *LogClient) GetSTH(ctx context.Context) (sth *ct.SignedTreeHead, err error) {
	var resp ct.GetSTHResponse
	_, err = c.GetAndParse(ctx, ct.GetSTHPath, nil, &resp)
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

	var ds ct.DigitallySigned
	if rest, err := tls.Unmarshal(resp.TreeHeadSignature, &ds); err != nil {
		return nil, err
	} else if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data (%d bytes) after DigitallySigned", len(rest))
	}
	sth.TreeHeadSignature = ds
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

	// Build enough of a Merkle tree leaf for the verifier to work on.
	leaf := ct.MerkleTreeLeaf{
		Version:  sct.SCTVersion,
		LeafType: ct.TimestampedEntryLeafType,
		TimestampedEntry: &ct.TimestampedEntry{
			Timestamp:  sct.Timestamp,
			EntryType:  ctype,
			Extensions: sct.Extensions,
		},
	}
	if ctype == ct.X509LogEntryType {
		leaf.TimestampedEntry.X509Entry = &certData[0]
	} else {
		// Pre-certs are more complicated; we need the issuer key hash and the
		// DER-encoded TBSCertificate.  First, parse the issuer to get its
		// public key hash.
		if len(certData) < 2 {
			return fmt.Errorf("no issuer cert available for precert SCT validation")
		}
		issuer, err := x509.ParseCertificate(certData[1].Data)
		if err != nil {
			return fmt.Errorf("failed to parse issuer cert: %v", err)
		}
		issuerKeyHash := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)

		// Second, parse the pre-certificate to extract its DER-encoded
		// TBSCertificate, then post-process this to remove the CT poison
		// extension.
		cert, err := x509.ParseCertificate(certData[0].Data)
		if err != nil {
			return fmt.Errorf("failed to parse leaf pre-cert: %v", err)
		}
		defangedTBS, err := x509.RemoveCTPoison(cert.RawTBSCertificate)
		if err != nil {
			return fmt.Errorf("failed to remove poison extension: %v", err)
		}
		leaf.TimestampedEntry.PrecertEntry = &ct.PreCert{
			IssuerKeyHash:  issuerKeyHash,
			TBSCertificate: defangedTBS,
		}
	}
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
	var resp ct.GetSTHConsistencyResponse
	if _, err := c.GetAndParse(ctx, ct.GetSTHConsistencyPath, params, &resp); err != nil {
		return nil, err
	}
	return resp.Consistency, nil
}

// GetProofByHash returns an audit path for the hash of an SCT.
func (c *LogClient) GetProofByHash(ctx context.Context, hash []byte, treeSize uint64) (*ct.GetProofByHashResponse, error) {
	b64Hash := url.QueryEscape(base64.StdEncoding.EncodeToString(hash))
	base10 := 10
	params := map[string]string{
		"tree_size": strconv.FormatUint(treeSize, base10),
		"hash":      b64Hash,
	}
	var resp ct.GetProofByHashResponse
	if _, err := c.GetAndParse(ctx, ct.GetProofByHashPath, params, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetAcceptedRoots retrieves the set of acceptable root certificates for a log.
func (c *LogClient) GetAcceptedRoots(ctx context.Context) ([]ct.ASN1Cert, error) {
	var resp ct.GetRootsResponse
	if _, err := c.GetAndParse(ctx, ct.GetRootsPath, nil, &resp); err != nil {
		return nil, err
	}
	var roots []ct.ASN1Cert
	for _, cert64 := range resp.Certificates {
		cert, err := base64.StdEncoding.DecodeString(cert64)
		if err != nil {
			return nil, err
		}
		roots = append(roots, ct.ASN1Cert{Data: cert})
	}
	return roots, nil
}
