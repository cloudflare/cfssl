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

// ctclient is a command-line utility for interacting with CT logs.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/merkletree"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
)

var (
	logURI    = flag.String("log_uri", "http://ct.googleapis.com/rocketeer", "CT log base URI")
	logMMD    = flag.Duration("log_mmd", 24*time.Hour, "Log's maximum merge delay")
	pubKey    = flag.String("pub_key", "", "Name of file containing log's public key")
	certChain = flag.String("cert_chain", "", "Name of file containing certificate chain as concatenated PEM files")
	textOut   = flag.Bool("text", true, "Display certificates as text")
	getFirst  = flag.Int64("first", -1, "First entry to get")
	getLast   = flag.Int64("last", -1, "Last entry to get")
	treeSize  = flag.Int64("size", -1, "Tree size to query at")
	leafHash  = flag.String("leaf_hash", "", "Leaf hash to retrieve (as hex string)")
)

func ctTimestampToTime(ts uint64) time.Time {
	secs := int64(ts / 1000)
	msecs := int64(ts % 1000)
	return time.Unix(secs, msecs*1000000)
}

func signatureToString(signed *ct.DigitallySigned) string {
	return fmt.Sprintf("Signature: Hash=%v Sign=%v Value=%x", signed.Algorithm.Hash, signed.Algorithm.Signature, signed.Signature)
}

func getSTH(ctx context.Context, logClient *client.LogClient) {
	sth, err := logClient.GetSTH(ctx)
	if err != nil {
		log.Fatal(err)
	}
	// Display the STH
	when := ctTimestampToTime(sth.Timestamp)
	fmt.Printf("%v: Got STH for %v log (size=%d) at %v, hash %x\n", when, sth.Version, sth.TreeSize, *logURI, sth.SHA256RootHash)
	fmt.Printf("%v\n", signatureToString(&sth.TreeHeadSignature))
}

func addChain(ctx context.Context, logClient *client.LogClient) {
	if *certChain == "" {
		log.Fatalf("No certificate chain file specified with -cert_chain")
	}
	rest, err := ioutil.ReadFile(*certChain)
	if err != nil {
		log.Fatalf("Failed to read certificate file: %v", err)
	}
	var chain []ct.ASN1Cert
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			chain = append(chain, ct.ASN1Cert{Data: block.Bytes})
		}
	}
	if len(chain) == 0 {
		log.Fatalf("No certificates found in %s", *certChain)
	}

	// Examine the leaf to see if it looks like a pre-certificate.
	isPrecert := false
	leaf, err := x509.ParseCertificate(chain[0].Data)
	if err == nil {
		count, _ := x509util.OIDInExtensions(x509.OIDExtensionCTPoison, leaf.Extensions)
		if count > 0 {
			isPrecert = true
			fmt.Print("Uploading pre-certificate to log\n")
		}
	}

	var sct *ct.SignedCertificateTimestamp
	if isPrecert {
		sct, err = logClient.AddPreChain(ctx, chain)
	} else {
		sct, err = logClient.AddChain(ctx, chain)
	}
	if err != nil {
		if err, ok := err.(client.RspError); ok {
			log.Fatalf("Upload failed: %q, detail:\n  %s", err, string(err.Body))
		}
		log.Fatalf("Upload failed: %q", err)
	}
	// Calculate the leaf hash
	leafEntry := ct.CreateX509MerkleTreeLeaf(chain[0], sct.Timestamp)
	leafData, err := tls.Marshal(*leafEntry)
	if err != nil {
		log.Fatalf("Failed to tls.Marshal leaf: %v", err)
	}
	leafHash := sha256.Sum256(append([]byte{merkletree.LeafPrefix}, leafData...))

	// Display the SCT
	when := ctTimestampToTime(sct.Timestamp)
	fmt.Printf("Uploaded chain of %d certs to %v log at %v, timestamp: %v\n", len(chain), sct.SCTVersion, *logURI, when)
	fmt.Printf("LeafHash: %x\n", leafHash)
	fmt.Printf("Signature: %v\n", signatureToString(&sct.Signature))

	age := time.Now().Sub(when)
	if age > *logMMD {
		// SCT's timestamp is old enough that the certificate should be included.
		getInclusionProofForHash(ctx, logClient, leafHash[:])
	}
}

func getRoots(ctx context.Context, logClient *client.LogClient) {
	roots, err := logClient.GetAcceptedRoots(ctx)
	if err != nil {
		log.Fatal(err)
	}
	for _, root := range roots {
		showRawCert(root)
	}
}

func getEntries(ctx context.Context, logClient *client.LogClient) {
	if *getFirst == -1 {
		log.Fatal("No -first option supplied")
	}
	if *getLast == -1 {
		log.Fatal("No -last option supplied")
	}
	entries, err := logClient.GetEntries(ctx, *getFirst, *getLast)
	if err != nil {
		log.Fatal(err)
	}
	for _, entry := range entries {
		ts := entry.Leaf.TimestampedEntry
		when := ctTimestampToTime(ts.Timestamp)
		fmt.Printf("Index=%d Timestamp=%v ", entry.Index, when)
		switch ts.EntryType {
		case ct.X509LogEntryType:
			fmt.Printf("X.509 certificate:\n")
			showParsedCert(entry.X509Cert)
		case ct.PrecertLogEntryType:
			fmt.Printf("pre-certificate from issuer with keyhash %x:\n", entry.Precert.IssuerKeyHash)
			showRawCert(entry.Precert.Submitted)
		default:
			log.Fatalf("Unhandled log entry type %d", entry.Leaf.TimestampedEntry.EntryType)
		}
	}
}

func getInclusionProof(ctx context.Context, logClient *client.LogClient) {
	hash, err := hex.DecodeString(*leafHash)
	if err != nil || len(hash) != 32 {
		log.Fatal("No valid --leaf_hash supplied in hex")
	}
	getInclusionProofForHash(ctx, logClient, hash)
}

func getInclusionProofForHash(ctx context.Context, logClient *client.LogClient, hash []byte) {
	var sth *ct.SignedTreeHead
	size := *treeSize
	if size <= 0 {
		var err error
		sth, err = logClient.GetSTH(ctx)
		if err != nil {
			log.Fatalf("Failed to get current STH: %v", err)
		}
		size = int64(sth.TreeSize)
	}
	// Display the inclusion proof.
	rsp, err := logClient.GetProofByHash(ctx, hash, uint64(size))
	if err != nil {
		log.Fatalf("Failed to get-proof-by-hash: %v", err)
	}
	fmt.Printf("Inclusion proof for index %d in tree of size %d:\n", rsp.LeafIndex, size)
	for _, e := range rsp.AuditPath {
		fmt.Printf("  %x\n", e)
	}
	if sth != nil {
		// If we retrieved an STH we can verify the proof.
		verifier := merkletree.NewMerkleVerifier(func(data []byte) []byte {
			hash := sha256.Sum256(data)
			return hash[:]
		})
		if err := verifier.VerifyInclusionProofByHash(rsp.LeafIndex, int64(sth.TreeSize), rsp.AuditPath, sth.SHA256RootHash[:], hash); err != nil {
			log.Fatalf("Failed to VerifyInclusionProofByHash(%d, %d)=%v", rsp.LeafIndex, sth.TreeSize, err)
		}
		fmt.Printf("Verified that hash %x + proof = root hash %x\n", hash, sth.SHA256RootHash)
	}
}

func showRawCert(cert ct.ASN1Cert) {
	if *textOut {
		c, err := x509.ParseCertificate(cert.Data)
		if err != nil {
			log.Printf("Error parsing certificate: %q", err.Error())
			return
		}
		showParsedCert(c)
	} else {
		showPEMData(cert.Data)
	}
}

func showParsedCert(cert *x509.Certificate) {
	if *textOut {
		fmt.Printf("%s\n", x509util.CertificateToString(cert))
	} else {
		showPEMData(cert.Raw)
	}
}

func showPEMData(data []byte) {
	if err := pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: data}); err != nil {
		log.Printf("Failed to PEM encode cert: %q", err.Error())
	}
}

func dieWithUsage(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	fmt.Fprintf(os.Stderr, "Usage: ctclient [options] <cmd>\n"+
		"where cmd is one of:\n"+
		"   sth         retrieve signed tree head\n"+
		"   upload      upload cert chain and show SCT (needs -cert_chain)\n"+
		"   getroots    show accepted roots\n"+
		"   getentries  get log entries (needs -first and -last)\n"+
		"   inclusion   get inclusion proof (needs -leaf_hash and optionally -size)\n")
	os.Exit(1)
}

func main() {
	flag.Parse()
	httpClient := &http.Client{
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
	}
	var opts jsonclient.Options
	if *pubKey != "" {
		pubkey, err := ioutil.ReadFile(*pubKey)
		if err != nil {
			log.Fatal(err)
		}
		opts.PublicKey = string(pubkey)
	}
	logClient, err := client.New(*logURI, httpClient, opts)
	if err != nil {
		log.Fatal(err)
	}
	args := flag.Args()
	if len(args) != 1 {
		dieWithUsage("Need command argument")
	}
	ctx := context.Background()
	cmd := args[0]
	switch cmd {
	case "sth":
		getSTH(ctx, logClient)
	case "upload":
		addChain(ctx, logClient)
	case "getroots", "get_roots", "get-roots":
		getRoots(ctx, logClient)
	case "getentries", "get_entries", "get-entries":
		getEntries(ctx, logClient)
	case "inclusion", "inclusion-proof":
		getInclusionProof(ctx, logClient)
	default:
		dieWithUsage(fmt.Sprintf("Unknown command '%s'", cmd))
	}
}
