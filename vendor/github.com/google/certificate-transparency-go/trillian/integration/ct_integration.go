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

// Package integration holds test-only code for running tests on
// an integrated system of the CT personality and a Trillian log.
package integration

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/merkletree"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/trillian/ctfe"
	"github.com/google/certificate-transparency-go/trillian/ctfe/configpb"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
	"github.com/google/trillian/crypto/keys"
	"github.com/google/trillian/crypto/keyspb"
	"github.com/kylelemons/godebug/pretty"
	"golang.org/x/net/context/ctxhttp"

	ct "github.com/google/certificate-transparency-go"
	keyspem "github.com/google/trillian/crypto/keys/pem"
)

const (
	reqStatsRE = `^http_reqs{ep="(\w+)",logid="(\d+)"} (\d+)$`
	rspStatsRE = `^http_rsps{ep="(\w+)",logid="(\d+)",rc="(\d+)"} (?P<val>\d+)$`
)

// DefaultTransport is a http Transport more suited for use in the hammer
// context.
// In particular it increases the number of reusable connections to the same
// host. This helps to prevent starvation of ports through TIME_WAIT when
// using the hammer with a high number of parallel chain submissions.
var DefaultTransport = &http.Transport{
	Proxy: http.ProxyFromEnvironment,
	DialContext: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}).DialContext,
	MaxIdleConns:          100,
	MaxIdleConnsPerHost:   100,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

// Verifier is used to verify Merkle tree calculations.
var Verifier = merkletree.NewMerkleVerifier(func(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
})

// ClientPool describes an entity which produces LogClient instances.
type ClientPool interface {
	// Next returns the next LogClient instance to be used.
	Next() *client.LogClient
}

// RandomPool holds a collection of CT LogClient instances.
type RandomPool []*client.LogClient

var _ ClientPool = &RandomPool{}

// Next picks a random client from the pool.
func (p RandomPool) Next() *client.LogClient {
	if len(p) == 0 {
		return nil
	}
	return p[rand.Intn(len(p))]
}

// NewRandomPool creates a pool which returns a random client from list of servers.
func NewRandomPool(servers string, pubKey *keyspb.PublicKey, prefix string) (ClientPool, error) {
	opts := jsonclient.Options{
		PublicKeyDER: pubKey.GetDer(),
	}

	hc := &http.Client{Transport: DefaultTransport}

	var pool RandomPool
	for _, s := range strings.Split(servers, ",") {
		c, err := client.New(fmt.Sprintf("http://%s/%s", s, prefix), hc, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to create LogClient instance: %v", err)
		}
		pool = append(pool, c)
	}
	return &pool, nil
}

// testInfo holds per-test information.
type testInfo struct {
	prefix         string
	cfg            *configpb.LogConfig
	metricsServers string
	stats          *logStats
	pool           ClientPool
}

func (t *testInfo) checkStats() error {
	return t.stats.check(t.cfg, t.metricsServers)
}

func (t *testInfo) client() *client.LogClient {
	return t.pool.Next()
}

// awaitTreeSize loops until the an STH is retrieved that is the specified size (or larger, if exact is false).
func (t *testInfo) awaitTreeSize(ctx context.Context, size uint64, exact bool, mmd time.Duration) (*ct.SignedTreeHead, error) {
	var sth *ct.SignedTreeHead
	deadline := time.Now().Add(mmd)
	for sth == nil || sth.TreeSize < size {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("deadline for STH inclusion expired (MMD=%v)", mmd)
		}
		time.Sleep(200 * time.Millisecond)
		var err error
		sth, err = t.client().GetSTH(ctx)
		if t.stats != nil {
			t.stats.done(ctfe.GetSTHName, 200)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to get STH: %v", err)
		}
	}
	if exact && sth.TreeSize != size {
		return nil, fmt.Errorf("sth.TreeSize=%d; want 1", sth.TreeSize)
	}
	return sth, nil
}

// checkInclusionOf checks that a given certificate chain and assocated SCT are included
// under a signed tree head.
func (t *testInfo) checkInclusionOf(ctx context.Context, chain []ct.ASN1Cert, sct *ct.SignedCertificateTimestamp, sth *ct.SignedTreeHead) error {
	// Calculate leaf hash =  SHA256(0x00 | tls-encode(MerkleTreeLeaf))
	leaf := ct.MerkleTreeLeaf{
		Version:  ct.V1,
		LeafType: ct.TimestampedEntryLeafType,
		TimestampedEntry: &ct.TimestampedEntry{
			Timestamp:  sct.Timestamp,
			EntryType:  ct.X509LogEntryType,
			X509Entry:  &(chain[0]),
			Extensions: sct.Extensions,
		},
	}
	leafData, err := tls.Marshal(leaf)
	if err != nil {
		return fmt.Errorf("tls.Marshal(leaf[%d])=(nil,%v); want (_,nil)", 0, err)
	}
	leafHash := sha256.Sum256(append([]byte{merkletree.LeafPrefix}, leafData...))
	rsp, err := t.client().GetProofByHash(ctx, leafHash[:], sth.TreeSize)
	t.stats.done(ctfe.GetProofByHashName, 200)
	if err != nil {
		return fmt.Errorf("got GetProofByHash(sct[%d],size=%d)=(nil,%v); want (_,nil)", 0, sth.TreeSize, err)
	}
	if err := Verifier.VerifyInclusionProof(rsp.LeafIndex, int64(sth.TreeSize), rsp.AuditPath, sth.SHA256RootHash[:], leafData); err != nil {
		return fmt.Errorf("got VerifyInclusionProof(%d, %d,...)=%v", 0, sth.TreeSize, err)
	}
	return nil
}

// checkInclusionOfPreCert checks a pre-cert is included at given index.
func (t *testInfo) checkInclusionOfPreCert(ctx context.Context, tbs []byte, issuer *x509.Certificate, sct *ct.SignedCertificateTimestamp, sth *ct.SignedTreeHead) error {
	// Calculate leaf hash =  SHA256(0x00 | tls-encode(MerkleTreeLeaf))
	leaf := ct.MerkleTreeLeaf{
		Version:  ct.V1,
		LeafType: ct.TimestampedEntryLeafType,
		TimestampedEntry: &ct.TimestampedEntry{
			Timestamp: sct.Timestamp,
			EntryType: ct.PrecertLogEntryType,
			PrecertEntry: &ct.PreCert{
				IssuerKeyHash:  sha256.Sum256(issuer.RawSubjectPublicKeyInfo),
				TBSCertificate: tbs,
			},
			Extensions: sct.Extensions,
		},
	}
	leafData, err := tls.Marshal(leaf)
	if err != nil {
		return fmt.Errorf("tls.Marshal(precertLeaf)=(nil,%v); want (_,nil)", err)
	}
	leafHash := sha256.Sum256(append([]byte{merkletree.LeafPrefix}, leafData...))
	rsp, err := t.client().GetProofByHash(ctx, leafHash[:], sth.TreeSize)
	t.stats.done(ctfe.GetProofByHashName, 200)
	if err != nil {
		return fmt.Errorf("got GetProofByHash(sct, size=%d)=nil,%v", sth.TreeSize, err)
	}
	fmt.Printf("%s: Inclusion proof leaf %d @ %d -> root %d = %x\n", t.prefix, rsp.LeafIndex, sct.Timestamp, sth.TreeSize, rsp.AuditPath)
	if err := Verifier.VerifyInclusionProof(rsp.LeafIndex, int64(sth.TreeSize), rsp.AuditPath, sth.SHA256RootHash[:], leafData); err != nil {
		return fmt.Errorf("got VerifyInclusionProof(%d,%d,...)=%v; want nil", rsp.LeafIndex, sth.TreeSize, err)
	}
	if err := t.checkStats(); err != nil {
		return fmt.Errorf("unexpected stats check: %v", err)
	}
	return nil
}

// checkPreCertEntry retrieves a pre-cert from a known index and checks it.
func (t *testInfo) checkPreCertEntry(ctx context.Context, precertIndex int64, tbs []byte) error {
	precertEntries, err := t.client().GetEntries(ctx, precertIndex, precertIndex)
	t.stats.done(ctfe.GetEntriesName, 200)
	if err != nil {
		return fmt.Errorf("got GetEntries(%d,%d)=(nil,%v); want (_,nil)", precertIndex, precertIndex, err)
	}
	if len(precertEntries) != 1 {
		return fmt.Errorf("len(entries)=%d; want %d", len(precertEntries), 1)
	}
	leaf := precertEntries[0].Leaf
	ts := leaf.TimestampedEntry
	fmt.Printf("%s: Entry[%d] = {Index:%d Leaf:{Version:%v TS:{EntryType:%v Timestamp:%v}}}\n",
		t.prefix, precertIndex, precertEntries[0].Index, leaf.Version, ts.EntryType, timeFromMS(ts.Timestamp))

	if ts.EntryType != ct.PrecertLogEntryType {
		return fmt.Errorf("leaf[%d].ts.EntryType=%v; want PrecertLogEntryType", precertIndex, ts.EntryType)
	}
	if !bytes.Equal(ts.PrecertEntry.TBSCertificate, tbs) {
		return fmt.Errorf("leaf[%d].ts.PrecertEntry differs from originally uploaded cert", precertIndex)
	}
	if err := t.checkStats(); err != nil {
		return fmt.Errorf("unexpected stats check: %v", err)
	}
	return nil
}

// RunCTIntegrationForLog tests against the log with configuration cfg, with a set
// of comma-separated server addresses given by servers, assuming that testdir holds
// a variety of test data files.
// nolint: gocyclo
func RunCTIntegrationForLog(cfg *configpb.LogConfig, servers, metricsServers, testdir string, mmd time.Duration, stats *logStats) error {
	ctx := context.Background()
	pool, err := NewRandomPool(servers, cfg.PublicKey, cfg.Prefix)
	if err != nil {
		return fmt.Errorf("failed to create pool: %v", err)
	}
	t := testInfo{
		prefix:         cfg.Prefix,
		cfg:            cfg,
		metricsServers: metricsServers,
		stats:          stats,
		pool:           pool,
	}

	if err := t.checkStats(); err != nil {
		return fmt.Errorf("unexpected stats check: %v", err)
	}

	// Stage 0: get accepted roots, which should just be the fake CA.
	roots, err := t.client().GetAcceptedRoots(ctx)
	t.stats.done(ctfe.GetRootsName, 200)
	if err != nil {
		return fmt.Errorf("got GetAcceptedRoots()=(nil,%v); want (_,nil)", err)
	}
	if len(roots) != 1 {
		return fmt.Errorf("len(GetAcceptedRoots())=%d; want 1", len(roots))
	}

	// Stage 1: get the STH, which should be empty.
	sth0, err := t.client().GetSTH(ctx)
	t.stats.done(ctfe.GetSTHName, 200)
	if err != nil {
		return fmt.Errorf("got GetSTH()=(nil,%v); want (_,nil)", err)
	}
	if sth0.Version != 0 {
		return fmt.Errorf("sth.Version=%v; want V1(0)", sth0.Version)
	}
	if sth0.TreeSize != 0 {
		return fmt.Errorf("sth.TreeSize=%d; want 0", sth0.TreeSize)
	}
	fmt.Printf("%s: Got STH(time=%q, size=%d): roothash=%x\n", t.prefix, timeFromMS(sth0.Timestamp), sth0.TreeSize, sth0.SHA256RootHash)

	// Stage 2: add a single cert (the intermediate CA), get an SCT.
	var scts [21]*ct.SignedCertificateTimestamp // 0=int-ca, 1-20=leaves
	var chain [21][]ct.ASN1Cert
	chain[0], err = GetChain(testdir, "int-ca.cert")
	if err != nil {
		return fmt.Errorf("failed to load certificate: %v", err)
	}
	scts[0], err = t.client().AddChain(ctx, chain[0])
	t.stats.done(ctfe.AddChainName, 200)
	if err != nil {
		return fmt.Errorf("got AddChain(int-ca.cert)=(nil,%v); want (_,nil)", err)
	}
	// Display the SCT
	fmt.Printf("%s: Uploaded int-ca.cert to %v log, got SCT(time=%q)\n", t.prefix, scts[0].SCTVersion, timeFromMS(scts[0].Timestamp))

	// Keep getting the STH until tree size becomes 1 and check the cert is included.
	sth1, err := t.awaitTreeSize(ctx, 1, true, mmd)
	if err != nil {
		return fmt.Errorf("AwaitTreeSize(1)=(nil,%v); want (_,nil)", err)
	}
	fmt.Printf("%s: Got STH(time=%q, size=%d): roothash=%x\n", t.prefix, timeFromMS(sth1.Timestamp), sth1.TreeSize, sth1.SHA256RootHash)
	if err := t.checkStats(); err != nil {
		return fmt.Errorf("unexpected stats check: %v", err)
	}
	t.checkInclusionOf(ctx, chain[0], scts[0], sth1)

	// Stage 2.5: add the same cert, expect an SCT with the same timestamp as before.
	var sctCopy *ct.SignedCertificateTimestamp
	sctCopy, err = t.client().AddChain(ctx, chain[0])
	if err != nil {
		return fmt.Errorf("got re-AddChain(int-ca.cert)=(nil,%v); want (_,nil)", err)
	}
	t.stats.done(ctfe.AddChainName, 200)
	if scts[0].Timestamp != sctCopy.Timestamp {
		return fmt.Errorf("got sct @ %v; want @ %v", sctCopy, scts[0])
	}

	// Stage 3: add a second cert, wait for tree size = 2
	chain[1], err = GetChain(testdir, "leaf01.chain")
	if err != nil {
		return fmt.Errorf("failed to load certificate: %v", err)
	}
	scts[1], err = t.client().AddChain(ctx, chain[1])
	t.stats.done(ctfe.AddChainName, 200)
	if err != nil {
		return fmt.Errorf("got AddChain(leaf01)=(nil,%v); want (_,nil)", err)
	}
	fmt.Printf("%s: Uploaded cert01.chain to %v log, got SCT(time=%q)\n", t.prefix, scts[1].SCTVersion, timeFromMS(scts[1].Timestamp))
	sth2, err := t.awaitTreeSize(ctx, 2, true, mmd)
	if err != nil {
		return fmt.Errorf("failed to get STH for size=1: %v", err)
	}
	fmt.Printf("%s: Got STH(time=%q, size=%d): roothash=%x\n", t.prefix, timeFromMS(sth2.Timestamp), sth2.TreeSize, sth2.SHA256RootHash)

	// Stage 4: get a consistency proof from size 1-> size 2.
	proof12, err := t.client().GetSTHConsistency(ctx, 1, 2)
	t.stats.done(ctfe.GetSTHConsistencyName, 200)
	if err != nil {
		return fmt.Errorf("got GetSTHConsistency(1, 2)=(nil,%v); want (_,nil)", err)
	}
	//                 sth2
	//                 / \
	//  sth1   =>      a b
	//    |            | |
	//   d0           d0 d1
	// So consistency proof is [b] and we should have:
	//   sth2 == SHA256(0x01 | sth1 | b)
	if len(proof12) != 1 {
		return fmt.Errorf("len(proof12)=%d; want 1", len(proof12))
	}
	if err := checkCTConsistencyProof(sth1, sth2, proof12); err != nil {
		return fmt.Errorf("got CheckCTConsistencyProof(sth1,sth2,proof12)=%v; want nil", err)
	}
	if err := t.checkStats(); err != nil {
		return fmt.Errorf("unexpected stats check: %v", err)
	}

	// Stage 4.5: get a consistency proof from size 0-> size 2, which should be empty.
	proof02, err := t.client().GetSTHConsistency(ctx, 0, 2)
	t.stats.done(ctfe.GetSTHConsistencyName, 200)
	if err != nil {
		return fmt.Errorf("got GetSTHConsistency(0, 2)=(nil,%v); want (_,nil)", err)
	}
	if len(proof02) != 0 {
		return fmt.Errorf("len(proof02)=%d; want 0", len(proof02))
	}
	if err := t.checkStats(); err != nil {
		return fmt.Errorf("unexpected stats check: %v", err)
	}

	// Stage 5: add certificates 2, 3, 4, 5,...N, for some random N in [4,20]
	atLeast := 4
	count := atLeast + rand.Intn(20-atLeast)
	for i := 2; i <= count; i++ {
		filename := fmt.Sprintf("leaf%02d.chain", i)
		chain[i], err = GetChain(testdir, filename)
		if err != nil {
			return fmt.Errorf("failed to load certificate: %v", err)
		}
		scts[i], err = t.client().AddChain(ctx, chain[i])
		t.stats.done(ctfe.AddChainName, 200)
		if err != nil {
			return fmt.Errorf("got AddChain(leaf%02d)=(nil,%v); want (_,nil)", i, err)
		}
	}
	fmt.Printf("%s: Uploaded leaf02-leaf%02d to log, got SCTs\n", t.prefix, count)
	if err := t.checkStats(); err != nil {
		return fmt.Errorf("unexpected stats check: %v", err)
	}

	// Stage 6: keep getting the STH until tree size becomes 1 + N (allows for int-ca.cert).
	treeSize := 1 + count
	sthN, err := t.awaitTreeSize(ctx, uint64(treeSize), true, mmd)
	if err != nil {
		return fmt.Errorf("AwaitTreeSize(%d)=(nil,%v); want (_,nil)", treeSize, err)
	}
	fmt.Printf("%s: Got STH(time=%q, size=%d): roothash=%x\n", t.prefix, timeFromMS(sthN.Timestamp), sthN.TreeSize, sthN.SHA256RootHash)

	// Stage 7: get a consistency proof from 2->(1+N).
	proof2N, err := t.client().GetSTHConsistency(ctx, 2, uint64(treeSize))
	t.stats.done(ctfe.GetSTHConsistencyName, 200)
	if err != nil {
		return fmt.Errorf("got GetSTHConsistency(2, %d)=(nil,%v); want (_,nil)", treeSize, err)
	}
	fmt.Printf("%s: Proof size 2->%d: %x\n", t.prefix, treeSize, proof2N)
	if err := checkCTConsistencyProof(sth2, sthN, proof2N); err != nil {
		return fmt.Errorf("got CheckCTConsistencyProof(sth2,sthN,proof2N)=%v; want nil", err)
	}

	// Stage 8: get entries [1, N] (start at 1 to skip int-ca.cert)
	entries, err := t.client().GetEntries(ctx, 1, int64(count))
	t.stats.done(ctfe.GetEntriesName, 200)
	if err != nil {
		return fmt.Errorf("got GetEntries(1,%d)=(nil,%v); want (_,nil)", count, err)
	}
	if len(entries) < count {
		return fmt.Errorf("len(entries)=%d; want %d", len(entries), count)
	}
	gotHashes := make(map[[sha256.Size]byte]bool)
	wantHashes := make(map[[sha256.Size]byte]bool)
	for i, entry := range entries {
		leaf := entry.Leaf
		ts := leaf.TimestampedEntry
		if leaf.Version != 0 {
			return fmt.Errorf("leaf[%d].Version=%v; want V1(0)", i, leaf.Version)
		}
		if leaf.LeafType != ct.TimestampedEntryLeafType {
			return fmt.Errorf("leaf[%d].Version=%v; want TimestampedEntryLeafType", i, leaf.LeafType)
		}

		if ts.EntryType != ct.X509LogEntryType {
			return fmt.Errorf("leaf[%d].ts.EntryType=%v; want X509LogEntryType", i, ts.EntryType)
		}
		// The certificates might not be sequenced in the order they were uploaded, so
		// compare the set of hashes.
		gotHashes[sha256.Sum256(ts.X509Entry.Data)] = true
		wantHashes[sha256.Sum256(chain[i+1][0].Data)] = true
	}
	if diff := pretty.Compare(gotHashes, wantHashes); diff != "" {
		return fmt.Errorf("retrieved cert hashes don't match uploaded cert hashes, diff:\n%v", diff)
	}
	fmt.Printf("%s: Got entries [1:%d+1]\n", t.prefix, count)
	if err := t.checkStats(); err != nil {
		return fmt.Errorf("unexpected stats check: %v", err)
	}

	// Stage 9: get an audit proof for each certificate we have an SCT for.
	for i := 1; i <= count; i++ {
		t.checkInclusionOf(ctx, chain[i], scts[i], sthN)
	}
	fmt.Printf("%s: Got inclusion proofs [1:%d+1]\n", t.prefix, count)
	if err := t.checkStats(); err != nil {
		return fmt.Errorf("unexpected stats check: %v", err)
	}

	// Stage 10: attempt to upload a corrupt certificate.
	corruptChain := make([]ct.ASN1Cert, len(chain[1]))
	copy(corruptChain, chain[1])
	corruptAt := len(corruptChain[0].Data) - 3
	corruptChain[0].Data[corruptAt] = corruptChain[0].Data[corruptAt] + 1
	if sct, err := t.client().AddChain(ctx, corruptChain); err == nil {
		return fmt.Errorf("got AddChain(corrupt-cert)=(%+v,nil); want (nil,error)", sct)
	}
	t.stats.done(ctfe.AddChainName, 400)
	fmt.Printf("%s: AddChain(corrupt-cert)=nil,%v\n", t.prefix, err)

	// Stage 11: attempt to upload a certificate without chain.
	if sct, err := t.client().AddChain(ctx, chain[1][0:0]); err == nil {
		return fmt.Errorf("got AddChain(leaf-only)=(%+v,nil); want (nil,error)", sct)
	}
	t.stats.done(ctfe.AddChainName, 400)
	fmt.Printf("%s: AddChain(leaf-only)=nil,%v\n", t.prefix, err)
	if err := t.checkStats(); err != nil {
		return fmt.Errorf("unexpected stats check: %v", err)
	}

	// Stage 12: build and add a pre-certificate.
	signer, err := MakeSigner(testdir)
	if err != nil {
		return fmt.Errorf("failed to retrieve signer for re-signing: %v", err)
	}
	issuer, err := x509.ParseCertificate(chain[0][0].Data)
	if err != nil {
		return fmt.Errorf("failed to parse issuer for precert: %v", err)
	}
	prechain, tbs, err := makePrecertChain(chain[1], issuer, signer, time.Time{} /*  notAfter */)
	if err != nil {
		return fmt.Errorf("failed to build pre-certificate: %v", err)
	}
	precertSCT, err := t.client().AddPreChain(ctx, prechain)
	t.stats.done(ctfe.AddPreChainName, 200)
	if err != nil {
		return fmt.Errorf("got AddPreChain()=(nil,%v); want (_,nil)", err)
	}
	fmt.Printf("%s: Uploaded precert to %v log, got SCT(time=%q)\n", t.prefix, precertSCT.SCTVersion, timeFromMS(precertSCT.Timestamp))
	treeSize++
	sthN1, err := t.awaitTreeSize(ctx, uint64(treeSize), true, mmd)
	if err != nil {
		return fmt.Errorf("AwaitTreeSize(%d)=(nil,%v); want (_,nil)", treeSize, err)
	}
	fmt.Printf("%s: Got STH(time=%q, size=%d): roothash=%x\n", t.prefix, timeFromMS(sthN1.Timestamp), sthN1.TreeSize, sthN1.SHA256RootHash)

	// Stage 13: retrieve and check pre-cert.
	precertIndex := int64(count + 1)
	if err := t.checkPreCertEntry(ctx, precertIndex, tbs); err != nil {
		return fmt.Errorf("failed to check pre-cert entry: %v", err)
	}

	// Stage 14: get an inclusion proof for the precert.
	if err := t.checkInclusionOfPreCert(ctx, tbs, issuer, precertSCT, sthN1); err != nil {
		return fmt.Errorf("failed to check inclusion of pre-cert entry: %v", err)
	}

	// Stage 15: invalid consistency proof
	if rsp, err := t.client().GetSTHConsistency(ctx, 2, 299); err == nil {
		return fmt.Errorf("got GetSTHConsistency(2,299)=(%+v,nil); want (nil,_)", rsp)
	}
	t.stats.done(ctfe.GetSTHConsistencyName, 400)
	fmt.Printf("%s: GetSTHConsistency(2,299)=(nil,_)\n", t.prefix)

	// Stage 16: invalid inclusion proof; expect a client.RspError{404}.
	wrong := sha256.Sum256([]byte("simply wrong"))
	if rsp, err := t.client().GetProofByHash(ctx, wrong[:], sthN1.TreeSize); err == nil {
		return fmt.Errorf("got GetProofByHash(wrong, size=%d)=(%v,nil); want (nil,_)", sthN1.TreeSize, rsp)
	} else if rspErr, ok := err.(client.RspError); ok {
		if rspErr.StatusCode != http.StatusNotFound {
			return fmt.Errorf("got GetProofByHash(wrong)=_, %d; want (nil, 404)", rspErr.StatusCode)
		}
	} else {
		return fmt.Errorf("got GetProofByHash(wrong)=%+v (%T); want (client.RspError)", err, err)
	}
	t.stats.done(ctfe.GetProofByHashName, 404)
	fmt.Printf("%s: GetProofByHash(wrong,%d)=(nil,_)\n", t.prefix, sthN1.TreeSize)

	// Stage 17: build and add a pre-certificate signed by a pre-issuer.
	preIssuerChain, preTBS, err := makePreIssuerPrecertChain(chain[1], issuer, signer)
	if err != nil {
		return fmt.Errorf("failed to build pre-issued pre-certificate: %v", err)
	}
	preIssuerCertSCT, err := pool.Next().AddPreChain(ctx, preIssuerChain)
	stats.done(ctfe.AddPreChainName, 200)
	if err != nil {
		return fmt.Errorf("got AddPreChain()=(nil,%v); want (_,nil)", err)
	}
	fmt.Printf("%s: Uploaded pre-issued precert to %v log, got SCT(time=%q)\n", t.prefix, precertSCT.SCTVersion, timeFromMS(precertSCT.Timestamp))
	treeSize++
	sthN2, err := t.awaitTreeSize(ctx, uint64(treeSize), true, mmd)
	if err != nil {
		return fmt.Errorf("AwaitTreeSize(%d)=(nil,%v); want (_,nil)", treeSize, err)
	}
	fmt.Printf("%s: Got STH(time=%q, size=%d): roothash=%x\n", t.prefix, timeFromMS(sthN2.Timestamp), sthN2.TreeSize, sthN2.SHA256RootHash)

	// Stage 18: retrieve and check pre-issued pre-cert.
	preIssuerCertIndex := int64(count + 2)
	if err := t.checkPreCertEntry(ctx, preIssuerCertIndex, preTBS); err != nil {
		return fmt.Errorf("failed to check pre-issued pre-cert entry: %v", err)
	}

	// Stage 19: get an inclusion proof for the pre-issued precert.
	if err := t.checkInclusionOfPreCert(ctx, preTBS, issuer, preIssuerCertSCT, sthN2); err != nil {
		return fmt.Errorf("failed to check inclusion of pre-cert entry: %v", err)
	}

	// Final stats check.
	if err := t.checkStats(); err != nil {
		return fmt.Errorf("unexpected stats check: %v", err)
	}
	return nil
}

// timeFromMS converts a timestamp in milliseconds (as used in CT) to a time.Time.
func timeFromMS(ts uint64) time.Time {
	secs := int64(ts / 1000)
	msecs := int64(ts % 1000)
	return time.Unix(secs, msecs*1000000)
}

// GetChain retrieves a certificate from a file of the given name and directory.
func GetChain(dir, path string) ([]ct.ASN1Cert, error) {
	certdata, err := ioutil.ReadFile(filepath.Join(dir, path))
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %v", err)
	}
	return CertsFromPEM(certdata), nil
}

// CertsFromPEM loads X.509 certificates from the provided PEM-encoded data.
func CertsFromPEM(data []byte) []ct.ASN1Cert {
	var chain []ct.ASN1Cert
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			chain = append(chain, ct.ASN1Cert{Data: block.Bytes})
		}
	}
	return chain
}

// checkCTConsistencyProof checks the given consistency proof.
func checkCTConsistencyProof(sth1, sth2 *ct.SignedTreeHead, proof [][]byte) error {
	return Verifier.VerifyConsistencyProof(int64(sth1.TreeSize), int64(sth2.TreeSize),
		sth1.SHA256RootHash[:], sth2.SHA256RootHash[:], proof)
}

// makePrecertChain builds a precert chain based from the given cert chain and cert, converting and
// re-signing relative to the given issuer.
func makePrecertChain(chain []ct.ASN1Cert, issuer *x509.Certificate, signer crypto.Signer, notAfter time.Time) ([]ct.ASN1Cert, []byte, error) {
	prechain := make([]ct.ASN1Cert, len(chain))
	copy(prechain[1:], chain[1:])

	cert, err := x509.ParseCertificate(chain[0].Data)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate to build precert from: %v", err)
	}
	cert.NotAfter = notAfter

	prechain[0].Data, err = buildNewPrecertData(cert, issuer, signer)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	// For later verification, build the leaf TBS data that is included in the log.
	tbs, err := buildLeafTBS(prechain[0].Data, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build leaf TBSCertificate: %v", err)
	}
	return prechain, tbs, nil
}

// buildNewPrecertData creates a new pre-certificate based on the given template cert (which is
// modified)
func buildNewPrecertData(cert, issuer *x509.Certificate, signer crypto.Signer) ([]byte, error) {
	// Randomize the subject key ID.
	randData := make([]byte, 128)
	if _, err := cryptorand.Read(randData); err != nil {
		return nil, fmt.Errorf("failed to read random data: %v", err)
	}
	cert.SubjectKeyId = randData

	// Add the CT poison extension.
	cert.ExtraExtensions = append(cert.ExtraExtensions, pkix.Extension{
		Id:       x509.OIDExtensionCTPoison,
		Critical: true,
		Value:    []byte{0x05, 0x00}, // ASN.1 NULL
	})

	// Create a fresh certificate, signed by the issuer.
	cert.AuthorityKeyId = issuer.SubjectKeyId
	data, err := x509.CreateCertificate(cryptorand.Reader, cert, issuer, cert.PublicKey, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to CreateCertificate: %v", err)
	}
	return data, nil
}

// buildLeafTBS builds the raw pre-cert data (a DER-encoded TBSCertificate) that is included
// in the log.
func buildLeafTBS(precertData []byte, preIssuer *x509.Certificate) ([]byte, error) {
	reparsed, err := x509.ParseCertificate(precertData)
	if err != nil {
		return nil, fmt.Errorf("failed to re-parse created precertificate: %v", err)
	}
	return x509.BuildPrecertTBS(reparsed.RawTBSCertificate, preIssuer)
}

// makePreIssuerPrecertChain builds a precert chain where the pre-cert is signed by a new
// pre-issuer intermediate.
func makePreIssuerPrecertChain(chain []ct.ASN1Cert, issuer *x509.Certificate, signer crypto.Signer) ([]ct.ASN1Cert, []byte, error) {
	prechain := make([]ct.ASN1Cert, len(chain)+1)
	copy(prechain[2:], chain[1:])

	// Create a new private key and intermediate CA cert to go with it.
	preSigner, err := keys.NewFromSpec(&keyspb.Specification{
		Params: &keyspb.Specification_EcdsaParams{
			EcdsaParams: &keyspb.Specification_ECDSA{
				Curve: keyspb.Specification_ECDSA_P256,
			},
		},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create pre-issuer private key: %v", err)
	}

	preIssuerTemplate := *issuer
	preIssuerTemplate.RawSubject = nil
	preIssuerTemplate.Subject.CommonName += "PrecertIssuer"
	preIssuerTemplate.PublicKeyAlgorithm = x509.ECDSA
	preIssuerTemplate.PublicKey = preSigner.Public()
	preIssuerTemplate.ExtKeyUsage = append(preIssuerTemplate.ExtKeyUsage, x509.ExtKeyUsageCertificateTransparency)

	// Set a new subject-key-id for the intermediate (to ensure it's different from the true
	// issuer's subject-key-id).
	randData := make([]byte, 128)
	if _, err := cryptorand.Read(randData); err != nil {
		return nil, nil, fmt.Errorf("failed to read random data: %v", err)
	}
	preIssuerTemplate.SubjectKeyId = randData
	prechain[1].Data, err = x509.CreateCertificate(cryptorand.Reader, &preIssuerTemplate, issuer, preIssuerTemplate.PublicKey, signer)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create pre-issuer certificate: %v", err)
	}

	// Parse the pre-issuer back to a fully-populated x509.Certificate.
	preIssuer, err := x509.ParseCertificate(prechain[1].Data)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to re-parse generated pre-issuer: %v", err)
	}

	cert, err := x509.ParseCertificate(chain[0].Data)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate to build precert from: %v", err)
	}

	prechain[0].Data, err = buildNewPrecertData(cert, preIssuer, preSigner)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	if err := verifyChain(prechain); err != nil {
		return nil, nil, fmt.Errorf("failed to verify just-created prechain: %v", err)
	}

	// The leaf data has the poison removed and the issuance information changed.
	tbs, err := buildLeafTBS(prechain[0].Data, preIssuer)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build leaf TBSCertificate: %v", err)
	}
	return prechain, tbs, nil
}

// makeCertChain builds a new cert chain based from the given cert chain, changing SubjectKeyId and
// re-signing relative to the given issuer.
func makeCertChain(chain []ct.ASN1Cert, template, issuer *x509.Certificate, signer crypto.Signer, notAfter time.Time) ([]ct.ASN1Cert, error) {
	cert := *template
	cert.NotAfter = notAfter

	newchain := make([]ct.ASN1Cert, len(chain))
	copy(newchain[1:], chain[1:])

	// Randomize the subject key ID.
	randData := make([]byte, 128)
	if _, err := cryptorand.Read(randData); err != nil {
		return nil, fmt.Errorf("failed to read random data: %v", err)
	}
	cert.SubjectKeyId = randData

	// Create a fresh certificate, signed by the intermediate CA.
	var err error
	newchain[0].Data, err = x509.CreateCertificate(cryptorand.Reader, &cert, issuer, cert.PublicKey, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	return newchain, nil
}

// verifyChain checks that a chain of certificates validates locally.
func verifyChain(rawChain []ct.ASN1Cert) error {
	chain := make([]*x509.Certificate, 0, len(rawChain))
	for i, c := range rawChain {
		cert, err := x509.ParseCertificate(c.Data)
		if err != nil {
			return fmt.Errorf("failed to parse rawChain[%d]: %v", i, err)
		}
		chain = append(chain, cert)
	}

	// First verify signatures cert-by-cert.
	for i := 1; i < len(chain); i++ {
		issuer := chain[i]
		cert := chain[i-1]
		if err := cert.CheckSignatureFrom(issuer); err != nil {
			return fmt.Errorf("failed to check signature on rawChain[%d] using rawChain[%d]: %v", i-1, i, err)
		}
	}

	// Now verify the chain as a whole
	intermediatePool := x509.NewCertPool()
	for i := 1; i < len(chain); i++ {
		intermediatePool.AddCert(chain[i])
	}
	rootPool := x509.NewCertPool()
	rootPool.AddCert(chain[len(chain)-1])
	opts := x509.VerifyOptions{
		Roots:             rootPool,
		Intermediates:     intermediatePool,
		DisableTimeChecks: true,
		KeyUsages:         []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	chain[0].UnhandledCriticalExtensions = nil
	chains, err := chain[0].Verify(opts)
	if err != nil {
		return fmt.Errorf("chain[0].Verify(%+v) failed: %v", opts, err)
	}
	if len(chains) == 0 {
		return errors.New("no path to root found when trying to validate chains")
	}

	return nil
}

// MakeSigner creates a signer using the private key in the test directory.
func MakeSigner(testdir string) (crypto.Signer, error) {
	key, err := keyspem.ReadPrivateKeyFile(filepath.Join(testdir, "int-ca.privkey.pem"), "babelfish")
	if err != nil {
		return nil, fmt.Errorf("failed to load private key for re-signing: %v", err)
	}
	return key, nil
}

// Track HTTP requests/responses so we can check the stats exported by the log.
type logStats struct {
	logID            int64
	lastSCTTimestamp int
	lastSTHTimestamp int
	lastSTHTreesize  int
	reqs             map[string]int            // entrypoint =>count
	rsps             map[string]map[string]int // entrypoint => status => count

}

func newLogStats(logID int64) *logStats {
	stats := logStats{
		logID: logID,
		reqs:  make(map[string]int),
		rsps:  make(map[string]map[string]int),
	}
	for _, ep := range ctfe.Entrypoints {
		stats.rsps[string(ep)] = make(map[string]int)
	}
	return &stats
}

func (ls *logStats) done(ep ctfe.EntrypointName, rc int) {
	if ls == nil {
		return
	}
	ls.reqs[string(ep)]++
	ls.rsps[string(ep)][strconv.Itoa(rc)]++
}

func (ls *logStats) check(cfg *configpb.LogConfig, servers string) error {
	if ls == nil {
		return nil
	}
	reqsRE := regexp.MustCompile(reqStatsRE)
	rspsRE := regexp.MustCompile(rspStatsRE)

	ctx := context.Background()
	got := newLogStats(int64(ls.logID))
	for _, s := range strings.Split(servers, ",") {
		httpReq, err := http.NewRequest(http.MethodGet, "http://"+s+"/metrics", nil)
		if err != nil {
			return fmt.Errorf("failed to build GET request: %v", err)
		}
		c := new(http.Client)

		httpRsp, err := ctxhttp.Do(ctx, c, httpReq)
		if err != nil {
			return fmt.Errorf("getting stats failed: %v", err)
		}
		defer httpRsp.Body.Close()
		defer ioutil.ReadAll(httpRsp.Body)
		if httpRsp.StatusCode != http.StatusOK {
			return fmt.Errorf("got HTTP Status %q", httpRsp.Status)
		}

		scanner := bufio.NewScanner(httpRsp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			m := reqsRE.FindStringSubmatch(line)
			if m != nil {
				if m[2] == strconv.FormatInt(ls.logID, 10) {
					if val, err := strconv.Atoi(m[3]); err == nil {
						ep := m[1]
						got.reqs[ep] += val
					}
				}
				continue
			}
			m = rspsRE.FindStringSubmatch(line)
			if m != nil {
				if m[2] == strconv.FormatInt(ls.logID, 10) {
					if val, err := strconv.Atoi(m[4]); err == nil {
						ep := m[1]
						rc := m[3]
						got.rsps[ep][rc] += val
					}
				}
				continue
			}
		}
	}

	// Now compare accumulated actual stats with what we expect to see.
	if !reflect.DeepEqual(got.reqs, ls.reqs) {
		return fmt.Errorf("got reqs %+v; want %+v", got.reqs, ls.reqs)
	}
	if !reflect.DeepEqual(got.rsps, ls.rsps) {
		return fmt.Errorf("got rsps %+v; want %+v", got.rsps, ls.rsps)
	}
	return nil
}
