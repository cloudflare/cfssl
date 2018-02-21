// Copyright 2017 Google Inc. All Rights Reserved.
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

package integration

import (
	"context"
	"crypto"
	"crypto/sha256"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/golang/protobuf/ptypes"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/merkletree"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/trillian/ctfe"
	"github.com/google/certificate-transparency-go/trillian/ctfe/configpb"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/trillian/monitoring"

	ct "github.com/google/certificate-transparency-go"
)

const (
	// How many STHs and SCTs to hold on to.
	sthCount = 10
	sctCount = 10

	// How far beyond current tree size to request for invalid requests.
	invalidStretch = int64(1000000)
)

var (
	// Metrics are all per-log (label "logid"), but may also be
	// per-entrypoint (label "ep") or per-return-code (label "rc").
	once        sync.Once
	reqs        monitoring.Counter // logid, ep => value
	errs        monitoring.Counter // logid, ep => value
	rsps        monitoring.Counter // logid, ep, rc => value
	invalidReqs monitoring.Counter // logid, ep => value
)

// setupMetrics initializes all the exported metrics.
func setupMetrics(mf monitoring.MetricFactory) {
	reqs = mf.NewCounter("reqs", "Number of valid requests sent", "logid", "ep")
	errs = mf.NewCounter("errs", "Number of error responses received for valid requests", "logid", "ep")
	rsps = mf.NewCounter("rsps", "Number of responses received for valid requests", "logid", "ep", "rc")
	invalidReqs = mf.NewCounter("invalid_reqs", "Number of deliberately-invalid requests sent", "logid", "ep")
}

// errSkip indicates that a test operation should be skipped.
type errSkip struct{}

func (e errSkip) Error() string {
	return "test operation skipped"
}

// Limiter is an interface to allow different rate limiters to be used with the
// hammer.
type Limiter interface {
	Wait()
}

type unLimited struct{}

func (u unLimited) Wait() {
}

// HammerConfig provides configuration for a stress/load test.
type HammerConfig struct {
	// Configuration for the log.
	LogCfg *configpb.LogConfig
	// How to create process-wide metrics.
	MetricFactory monitoring.MetricFactory
	// Maximum merge delay.
	MMD time.Duration
	// Leaf certificate chain to use as template.
	LeafChain []ct.ASN1Cert
	// Parsed leaf certificate to use as template.
	LeafCert *x509.Certificate
	// Intermediate CA certificate chain to use as re-signing CA.
	CACert *x509.Certificate
	Signer crypto.Signer
	// ClientPool provides the clients used to make requests.
	ClientPool ClientPool
	// Bias values to favor particular log operations.
	EPBias HammerBias
	// Range of how many entries to get.
	MinGetEntries, MaxGetEntries int
	// OversizedGetEntries governs whether get-entries requests that go beyond the
	// current tree size are allowed (with a truncated response expected).
	OversizedGetEntries bool
	// Number of operations to perform.
	Operations uint64
	// Rate limiter
	Limiter Limiter
	// MaxParallelChains sets the upper limit for the number of parallel
	// add-*-chain requests to make when the biasing model says to perfom an add.
	MaxParallelChains int
	// EmitInterval defines how frequently stats are logged.
	EmitInterval time.Duration
	// IgnoreErrors controls whether a hammer run fails immediately on any error.
	IgnoreErrors bool
	// MaxRetryDuration governs how long to keep retrying when IgnoreErrors is true.
	MaxRetryDuration time.Duration
	// NotAfterOverride is used as cert and precert's NotAfter if not zeroed.
	// It takes precedence over automatic NotAfter fixing for temporal logs.
	NotAfterOverride time.Time
}

// HammerBias indicates the bias for selecting different log operations.
type HammerBias struct {
	Bias  map[ctfe.EntrypointName]int
	total int
	// InvalidChance gives the odds of performing an invalid operation, as the N in 1-in-N.
	InvalidChance map[ctfe.EntrypointName]int
}

// Choose randomly picks an operation to perform according to the biases.
func (hb HammerBias) Choose() ctfe.EntrypointName {
	if hb.total == 0 {
		for _, ep := range ctfe.Entrypoints {
			hb.total += hb.Bias[ep]
		}
	}
	which := rand.Intn(hb.total)
	for _, ep := range ctfe.Entrypoints {
		which -= hb.Bias[ep]
		if which < 0 {
			return ep
		}
	}
	panic("random choice out of range")
}

// Invalid randomly chooses whether an operation should be invalid.
func (hb HammerBias) Invalid(ep ctfe.EntrypointName) bool {
	chance := hb.InvalidChance[ep]
	if chance <= 0 {
		return false
	}
	return rand.Intn(chance) == 0
}

type submittedCert struct {
	leafData    []byte
	leafHash    [sha256.Size]byte
	sct         *ct.SignedCertificateTimestamp
	integrateBy time.Time
	precert     bool
}

// pendingCerts holds certificates that have been submitted that we want
// to check inclusion proofs for.  The array is ordered from oldest to
// most recent, but new entries are only appended when enough time has
// passed since the last append, so the SCTs that get checked are spread
// out across the MMD period.
type pendingCerts struct {
	mu    sync.Mutex
	certs [sctCount]*submittedCert
}

func (pc *pendingCerts) empty() bool {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	return pc.certs[0] == nil
}

// tryAppendCert locks mu, checks whether it's possible to append the cert, and
// appends it if so.
func (pc *pendingCerts) tryAppendCert(now time.Time, mmd time.Duration, submitted *submittedCert) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if pc.canAppend(now, mmd) {
		which := 0
		for ; which < sctCount; which++ {
			if pc.certs[which] == nil {
				break
			}
		}
		pc.certs[which] = submitted
	}
}

// canAppend checks whether a pending cert can be appended.
// It must be called with mu locked.
func (pc *pendingCerts) canAppend(now time.Time, mmd time.Duration) bool {
	if pc.certs[sctCount-1] != nil {
		return false // full already
	}
	if pc.certs[0] == nil {
		return true // nothing yet
	}
	// Only allow append if enough time has passed, namely MMD/#savedSCTs.
	last := sctCount - 1
	for ; last >= 0; last-- {
		if pc.certs[last] != nil {
			break
		}
	}
	lastTime := timeFromMS(pc.certs[last].sct.Timestamp)
	nextTime := lastTime.Add(mmd / sctCount)
	return now.After(nextTime)
}

// oldestIfMMDPassed returns the oldest submitted certificate if the maximum
// merge delay has passed, i.e. it is expected to be integrated as of now.  This
// function locks mu.
func (pc *pendingCerts) oldestIfMMDPassed(now time.Time) *submittedCert {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	if pc.certs[0] == nil {
		return nil
	}
	submitted := pc.certs[0]
	if !now.After(submitted.integrateBy) {
		// Oldest cert not due to be integrated yet, so neither will any others.
		return nil
	}
	return submitted
}

// dropOldest removes the oldest submitted certificate.
func (pc *pendingCerts) dropOldest() {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	// Can pop the oldest cert and shuffle the others along, which make room for
	// another cert to be stored.
	for i := 0; i < (sctCount - 1); i++ {
		pc.certs[i] = pc.certs[i+1]
	}
	pc.certs[sctCount-1] = nil
}

// hammerState tracks the operations that have been performed during a test run, including
// earlier SCTs/STHs for later checking.
type hammerState struct {
	cfg *HammerConfig
	mu  sync.RWMutex
	// STHs are arranged from later to earlier (so [0] is the most recent), and the
	// discovery of new STHs will push older ones off the end.
	sth [sthCount]*ct.SignedTreeHead
	// Submitted certs also run from later to earlier, but the discovery of new SCTs
	// does not affect the existing contents of the array, so if the array is full it
	// keeps the same elements.  Instead, the oldest entry is removed (and a space
	// created) when we are able to get an inclusion proof for it.
	pending pendingCerts
	// Operations that are required to fix dependencies.
	nextOp []ctfe.EntrypointName
	// notAfter is the NotAfter time used for new certs and precerts.
	notAfter time.Time
}

func newHammerState(cfg *HammerConfig) (*hammerState, error) {
	mf := cfg.MetricFactory
	if mf == nil {
		mf = monitoring.InertMetricFactory{}
	}
	once.Do(func() { setupMetrics(mf) })
	if cfg.MinGetEntries <= 0 {
		cfg.MinGetEntries = 1
	}
	if cfg.MaxGetEntries <= cfg.MinGetEntries {
		cfg.MaxGetEntries = cfg.MinGetEntries + 300
	}
	if cfg.EmitInterval <= 0 {
		cfg.EmitInterval = 10 * time.Second
	}
	if cfg.Limiter == nil {
		cfg.Limiter = unLimited{}
	}
	if cfg.MaxRetryDuration <= 0 {
		cfg.MaxRetryDuration = 60 * time.Second
	}

	notAfter, err := getNotAfter(cfg)
	if err != nil {
		return nil, err
	}
	glog.Infof("%v: using NotAfter = %v", cfg.LogCfg.Prefix, notAfter)

	state := hammerState{
		cfg:      cfg,
		nextOp:   make([]ctfe.EntrypointName, 0),
		notAfter: notAfter,
	}
	return &state, nil
}

// getNotAfter returns the NotAfter time to be used on new certs.
// If cfg.NotAfterOverride is non-zero, it takes precedence and is returned.
// If cfg.LogCfg is a temporal log, the halfway point between its NotAfterStart and NotAfterLimit is
// returned.
// Otherwise a zeroed time is returned.
func getNotAfter(cfg *HammerConfig) (time.Time, error) {
	if cfg.NotAfterOverride.UnixNano() > 0 {
		return cfg.NotAfterOverride, nil
	}
	if cfg.LogCfg.NotAfterStart == nil || cfg.LogCfg.NotAfterLimit == nil {
		return time.Time{}, nil
	}
	start, err := ptypes.Timestamp(cfg.LogCfg.NotAfterStart)
	if err != nil {
		return time.Time{}, fmt.Errorf("error parsing NotAfterStart for %v: %v", cfg.LogCfg.Prefix, cfg.LogCfg.NotAfterStart)
	}
	limit, err := ptypes.Timestamp(cfg.LogCfg.NotAfterLimit)
	if err != nil {
		return time.Time{}, fmt.Errorf("error parsing NotAfterLimit for %v: %v", cfg.LogCfg.Prefix, cfg.LogCfg.NotAfterLimit)
	}
	return time.Unix(0, (limit.UnixNano()-start.UnixNano())/2+start.UnixNano()), nil
}

func (s *hammerState) client() *client.LogClient {
	return s.cfg.ClientPool.Next()
}

func (s *hammerState) lastTreeSize() uint64 {
	if s.sth[0] == nil {
		return 0
	}
	return s.sth[0].TreeSize
}

func (s *hammerState) needOps(ops ...ctfe.EntrypointName) {
	glog.V(2).Infof("need operations %+v to satisfy dependencies", ops)
	s.nextOp = append(s.nextOp, ops...)
}

// addMultiple calls the passed in function a random number
// (1 <= n < MaxParallelChains) of times.
// The first of any errors returned by calls to addOne will be returned by this function.
func (s *hammerState) addMultiple(ctx context.Context, addOne func(context.Context) error) error {
	var wg sync.WaitGroup
	numAdds := rand.Intn(s.cfg.MaxParallelChains) + 1
	errs := make(chan error, numAdds)
	for i := 0; i < numAdds; i++ {
		wg.Add(1)
		go func() {
			if err := addOne(ctx); err != nil {
				errs <- err
			}
			wg.Done()
		}()
	}
	wg.Wait()
	select {
	case err := <-errs:
		return err
	default:
	}
	return nil
}

func (s *hammerState) addChain(ctx context.Context) error {
	chain, err := makeCertChain(s.cfg.LeafChain, s.cfg.LeafCert, s.cfg.CACert, s.cfg.Signer, s.notAfter)
	if err != nil {
		return fmt.Errorf("failed to make fresh cert: %v", err)
	}
	sct, err := s.client().AddChain(ctx, chain)
	if err != nil {
		return fmt.Errorf("failed to add-chain: %v", err)
	}
	glog.V(2).Infof("%s: Uploaded cert, got SCT(time=%q)", s.cfg.LogCfg.Prefix, timeFromMS(sct.Timestamp))
	// Calculate leaf hash =  SHA256(0x00 | tls-encode(MerkleTreeLeaf))
	submitted := submittedCert{precert: false, sct: sct}
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
	submitted.integrateBy = timeFromMS(sct.Timestamp).Add(s.cfg.MMD)
	submitted.leafData, err = tls.Marshal(leaf)
	if err != nil {
		return fmt.Errorf("failed to tls.Marshal leaf cert: %v", err)
	}
	submitted.leafHash = sha256.Sum256(append([]byte{merkletree.LeafPrefix}, submitted.leafData...))
	s.pending.tryAppendCert(time.Now(), s.cfg.MMD, &submitted)
	glog.V(3).Infof("%s: Uploaded cert has leaf-hash %x", s.cfg.LogCfg.Prefix, submitted.leafHash)
	return nil
}

func (s *hammerState) addChainInvalid(ctx context.Context) error {
	// Invalid because it's a pre-cert chain, not a cert chain.
	chain, _, err := makePrecertChain(s.cfg.LeafChain, s.cfg.CACert, s.cfg.Signer, s.notAfter)
	if err != nil {
		return fmt.Errorf("failed to make fresh cert: %v", err)
	}
	sct, err := s.client().AddChain(ctx, chain)
	if err == nil {
		return fmt.Errorf("unexpected success: add-chain: %+v", sct)
	}
	return nil
}

func (s *hammerState) addPreChain(ctx context.Context) error {
	prechain, tbs, err := makePrecertChain(s.cfg.LeafChain, s.cfg.CACert, s.cfg.Signer, s.notAfter)
	if err != nil {
		return fmt.Errorf("failed to make fresh pre-cert: %v", err)
	}
	sct, err := s.client().AddPreChain(ctx, prechain)
	if err != nil {
		return fmt.Errorf("failed to add-pre-chain: %v", err)
	}
	glog.V(2).Infof("%s: Uploaded pre-cert, got SCT(time=%q)", s.cfg.LogCfg.Prefix, timeFromMS(sct.Timestamp))
	// Calculate leaf hash =  SHA256(0x00 | tls-encode(MerkleTreeLeaf))
	submitted := submittedCert{precert: true, sct: sct}
	leaf := ct.MerkleTreeLeaf{
		Version:  ct.V1,
		LeafType: ct.TimestampedEntryLeafType,
		TimestampedEntry: &ct.TimestampedEntry{
			Timestamp: sct.Timestamp,
			EntryType: ct.PrecertLogEntryType,
			PrecertEntry: &ct.PreCert{
				IssuerKeyHash:  sha256.Sum256(s.cfg.CACert.RawSubjectPublicKeyInfo),
				TBSCertificate: tbs,
			},
			Extensions: sct.Extensions,
		},
	}
	submitted.integrateBy = timeFromMS(sct.Timestamp).Add(s.cfg.MMD)
	submitted.leafData, err = tls.Marshal(leaf)
	if err != nil {
		return fmt.Errorf("tls.Marshal(precertLeaf)=(nil,%v); want (_,nil)", err)
	}
	submitted.leafHash = sha256.Sum256(append([]byte{merkletree.LeafPrefix}, submitted.leafData...))
	s.pending.tryAppendCert(time.Now(), s.cfg.MMD, &submitted)
	glog.V(3).Infof("%s: Uploaded pre-cert has leaf-hash %x", s.cfg.LogCfg.Prefix, submitted.leafHash)
	return nil
}

func (s *hammerState) addPreChainInvalid(ctx context.Context) error {
	// Invalid because it's a cert chain, not a pre-cert chain.
	prechain, err := makeCertChain(s.cfg.LeafChain, s.cfg.LeafCert, s.cfg.CACert, s.cfg.Signer, s.notAfter)
	if err != nil {
		return fmt.Errorf("failed to make fresh pre-cert: %v", err)
	}
	sct, err := s.client().AddPreChain(ctx, prechain)
	if err == nil {
		return fmt.Errorf("unexpected success: add-pre-chain: %+v", sct)
	}
	return nil
}

func (s *hammerState) getSTH(ctx context.Context) error {
	// Shuffle earlier STHs along.
	for i := sthCount - 1; i > 0; i-- {
		s.sth[i] = s.sth[i-1]
	}
	var err error
	s.sth[0], err = s.client().GetSTH(ctx)
	if err != nil {
		return fmt.Errorf("failed to get-sth: %v", err)
	}
	glog.V(2).Infof("%s: Got STH(time=%q, size=%d)", s.cfg.LogCfg.Prefix, timeFromMS(s.sth[0].Timestamp), s.sth[0].TreeSize)
	return nil
}

func (s *hammerState) getSTHConsistency(ctx context.Context) error {
	// Get current size, and pick an earlier size
	sthNow, err := s.client().GetSTH(ctx)
	if err != nil {
		return fmt.Errorf("failed to get-sth for current tree: %v", err)
	}
	which := rand.Intn(sthCount)
	if s.sth[which] == nil {
		glog.V(3).Infof("%s: skipping get-sth-consistency as no earlier STH", s.cfg.LogCfg.Prefix)
		s.needOps(ctfe.GetSTHName)
		return errSkip{}
	}
	if s.sth[which].TreeSize == 0 {
		glog.V(3).Infof("%s: skipping get-sth-consistency as no earlier STH", s.cfg.LogCfg.Prefix)
		s.needOps(ctfe.AddChainName, ctfe.GetSTHName)
		return errSkip{}
	}
	if s.sth[which].TreeSize == sthNow.TreeSize {
		glog.V(3).Infof("%s: skipping get-sth-consistency as same size (%d)", s.cfg.LogCfg.Prefix, sthNow.TreeSize)
		s.needOps(ctfe.AddChainName, ctfe.GetSTHName)
		return errSkip{}
	}

	proof, err := s.client().GetSTHConsistency(ctx, s.sth[which].TreeSize, sthNow.TreeSize)
	if err != nil {
		return fmt.Errorf("failed to get-sth-consistency(%d, %d): %v", s.sth[which].TreeSize, sthNow.TreeSize, err)
	}
	if err := checkCTConsistencyProof(s.sth[which], sthNow, proof); err != nil {
		return fmt.Errorf("get-sth-consistency(%d, %d) proof check failed: %v", s.sth[which].TreeSize, sthNow.TreeSize, err)
	}
	glog.V(2).Infof("%s: Got STH consistency proof (size=%d => %d) len %d",
		s.cfg.LogCfg.Prefix, s.sth[which].TreeSize, sthNow.TreeSize, len(proof))
	return nil
}

func (s *hammerState) getSTHConsistencyInvalid(ctx context.Context) error {
	if s.lastTreeSize() == 0 {
		return nil
	}
	// Invalid because it's beyond the tree size.
	first := s.lastTreeSize() + uint64(invalidStretch)
	second := first + 100
	proof, err := s.client().GetSTHConsistency(ctx, first, second)
	if err == nil {
		return fmt.Errorf("unexpected success: get-sth-consistency(%d, %d): %+v", first, second, proof)
	}
	return nil
}

func (s *hammerState) getProofByHash(ctx context.Context) error {
	submitted := s.pending.oldestIfMMDPassed(time.Now())
	if submitted == nil {
		// No SCT that is guaranteed to be integrated, so move on.
		return errSkip{}
	}
	// Get an STH that should include this submitted [pre-]cert.
	sth, err := s.client().GetSTH(ctx)
	if err != nil {
		return fmt.Errorf("failed to get-sth for proof: %v", err)
	}
	// Get and check an inclusion proof.
	rsp, err := s.client().GetProofByHash(ctx, submitted.leafHash[:], sth.TreeSize)
	if err != nil {
		return fmt.Errorf("failed to get-proof-by-hash(size=%d) on cert with SCT @ %v: %v, %+v", sth.TreeSize, timeFromMS(submitted.sct.Timestamp), err, rsp)
	}
	if err := Verifier.VerifyInclusionProof(rsp.LeafIndex, int64(sth.TreeSize), rsp.AuditPath, sth.SHA256RootHash[:], submitted.leafData); err != nil {
		return fmt.Errorf("failed to VerifyInclusionProof(%d, %d)=%v", rsp.LeafIndex, sth.TreeSize, err)
	}
	s.pending.dropOldest()
	return nil
}

func (s *hammerState) getProofByHashInvalid(ctx context.Context) error {
	// Invalid because the hash is wrong.
	rsp, err := s.client().GetProofByHash(ctx, []byte{0x01, 0x02}, 1)
	if err == nil {
		return fmt.Errorf("unexpected success: get-proof-by-hash(0x0102, 1): %+v", rsp)
	}
	return nil
}

func (s *hammerState) getEntries(ctx context.Context) error {
	if s.sth[0] == nil {
		glog.V(3).Infof("%s: skipping get-entries as no earlier STH", s.cfg.LogCfg.Prefix)
		s.needOps(ctfe.GetSTHName)
		return errSkip{}
	}
	if s.sth[0].TreeSize == 0 {
		if s.pending.empty() {
			glog.V(3).Infof("%s: skipping get-entries as tree size 0", s.cfg.LogCfg.Prefix)
			s.needOps(ctfe.AddChainName, ctfe.GetSTHName)
			return errSkip{}
		}
		glog.V(3).Infof("%s: skipping get-entries as STH stale", s.cfg.LogCfg.Prefix)
		s.needOps(ctfe.GetSTHName)
		return errSkip{}
	}
	// Entry indices are zero-based, and may or may not be allowed to extend
	// beyond current tree size (RFC 6962 s4.6).
	first := rand.Intn(int(s.lastTreeSize()))
	span := s.cfg.MaxGetEntries - s.cfg.MinGetEntries
	count := s.cfg.MinGetEntries + rand.Intn(int(span))
	last := first + count

	if !s.cfg.OversizedGetEntries && last >= int(s.sth[0].TreeSize) {
		last = int(s.sth[0].TreeSize) - 1
		count = last - first + 1
	}

	entries, err := s.client().GetEntries(ctx, int64(first), int64(last))
	if err != nil {
		return fmt.Errorf("failed to get-entries(%d,%d): %v", first, last, err)
	}
	for i, entry := range entries {
		if want := int64(first + i); entry.Index != want {
			return fmt.Errorf("leaf[%d].LeafIndex=%d; want %d", i, entry.Index, want)
		}
		leaf := entry.Leaf
		if leaf.Version != 0 {
			return fmt.Errorf("leaf[%d].Version=%v; want V1(0)", i, leaf.Version)
		}
		if leaf.LeafType != ct.TimestampedEntryLeafType {
			return fmt.Errorf("leaf[%d].Version=%v; want TimestampedEntryLeafType", i, leaf.LeafType)
		}
		ts := leaf.TimestampedEntry
		if ts.EntryType != ct.X509LogEntryType && ts.EntryType != ct.PrecertLogEntryType {
			return fmt.Errorf("leaf[%d].ts.EntryType=%v; want {X509,Precert}LogEntryType", i, ts.EntryType)
		}
	}
	glog.V(2).Infof("%s: Got entries [%d:%d)\n", s.cfg.LogCfg.Prefix, first, first+len(entries))
	return nil
}

func (s *hammerState) getEntriesInvalid(ctx context.Context) error {
	if s.lastTreeSize() == 0 {
		return nil
	}
	// Invalid because it's beyond the tree size.
	last := int64(s.lastTreeSize()) + invalidStretch
	first := last - 4
	entries, err := s.client().GetEntries(ctx, first, last)
	if err == nil {
		return fmt.Errorf("unexpected success: get-entries(%d,%d): %d entries", first, last, len(entries))
	}
	return nil
}

func (s *hammerState) getRoots(ctx context.Context) error {
	roots, err := s.client().GetAcceptedRoots(ctx)
	if err != nil {
		return fmt.Errorf("failed to get-roots: %v", err)
	}
	glog.V(2).Infof("%s: Got roots (len=%d)", s.cfg.LogCfg.Prefix, len(roots))
	return nil
}

func sthSize(sth *ct.SignedTreeHead) string {
	if sth == nil {
		return "n/a"
	}
	return fmt.Sprintf("%d", sth.TreeSize)
}

func (s *hammerState) label() string {
	return strconv.FormatInt(s.cfg.LogCfg.LogId, 10)
}

func (s *hammerState) String() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	details := ""
	statusOK := strconv.Itoa(http.StatusOK)
	totalReqs := 0
	totalInvalidReqs := 0
	totalErrs := 0
	for _, ep := range ctfe.Entrypoints {
		reqCount := int(reqs.Value(s.label(), string(ep)))
		totalReqs += reqCount
		if s.cfg.EPBias.Bias[ep] > 0 {
			details += fmt.Sprintf(" %s=%d/%d", ep, int(rsps.Value(s.label(), string(ep), statusOK)), reqCount)
		}
		totalInvalidReqs += int(invalidReqs.Value(s.label(), string(ep)))
		totalErrs += int(errs.Value(s.label(), string(ep)))
	}
	return fmt.Sprintf("%10s: lastSTH.size=%s ops: total=%d invalid=%d errs=%v%s", s.cfg.LogCfg.Prefix, sthSize(s.sth[0]), totalReqs, totalInvalidReqs, totalErrs, details)
}

func (s *hammerState) performOp(ctx context.Context, ep ctfe.EntrypointName) (int, error) {
	s.cfg.Limiter.Wait()
	status := http.StatusOK
	var err error
	switch ep {
	case ctfe.AddChainName:
		err = s.addMultiple(ctx, s.addChain)
	case ctfe.AddPreChainName:
		err = s.addMultiple(ctx, s.addPreChain)
	case ctfe.GetSTHName:
		err = s.getSTH(ctx)
	case ctfe.GetSTHConsistencyName:
		err = s.getSTHConsistency(ctx)
	case ctfe.GetProofByHashName:
		err = s.getProofByHash(ctx)
	case ctfe.GetEntriesName:
		err = s.getEntries(ctx)
	case ctfe.GetRootsName:
		err = s.getRoots(ctx)
	case ctfe.GetEntryAndProofName:
		status = http.StatusNotImplemented
		glog.V(2).Infof("%s: hammering entrypoint %s not yet implemented", s.cfg.LogCfg.Prefix, ep)
	default:
		err = fmt.Errorf("internal error: unknown entrypoint %s selected", ep)
	}
	return status, err
}

func (s *hammerState) performInvalidOp(ctx context.Context, ep ctfe.EntrypointName) error {
	s.cfg.Limiter.Wait()
	switch ep {
	case ctfe.AddChainName:
		return s.addChainInvalid(ctx)
	case ctfe.AddPreChainName:
		return s.addPreChainInvalid(ctx)
	case ctfe.GetSTHConsistencyName:
		return s.getSTHConsistencyInvalid(ctx)
	case ctfe.GetProofByHashName:
		return s.getProofByHashInvalid(ctx)
	case ctfe.GetEntriesName:
		return s.getEntriesInvalid(ctx)
	case ctfe.GetSTHName, ctfe.GetRootsName:
		return fmt.Errorf("no invalid request possible for entrypoint %s", ep)
	case ctfe.GetEntryAndProofName:
		return fmt.Errorf("hammering entrypoint %s not yet implemented", ep)
	}
	return fmt.Errorf("internal error: unknown entrypoint %s", ep)
}

func (s *hammerState) chooseOp() (ctfe.EntrypointName, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.nextOp) > 0 {
		ep := s.nextOp[0]
		s.nextOp = s.nextOp[1:]
		if s.cfg.EPBias.Bias[ep] > 0 {
			return ep, false
		}
	}
	ep := s.cfg.EPBias.Choose()
	return ep, s.cfg.EPBias.Invalid(ep)
}

// Perform a random operation on the log, retrying if necessary. If non-empty, the
// returned entrypoint should be performed next to unblock dependencies.
func (s *hammerState) retryOneOp(ctx context.Context) error {
	ep, invalid := s.chooseOp()
	if invalid {
		glog.V(3).Infof("perform invalid %s operation", ep)
		invalidReqs.Inc(s.label(), string(ep))
		return s.performInvalidOp(ctx, ep)
	}

	glog.V(3).Infof("perform %s operation", ep)
	status := http.StatusOK
	deadline := time.Now().Add(s.cfg.MaxRetryDuration)

	var err error
	done := false
	for !done {
		s.mu.Lock()

		start := time.Now()
		reqs.Inc(s.label(), string(ep))
		status, err = s.performOp(ctx, ep)
		period := time.Now().Sub(start)

		switch err.(type) {
		case nil:
			rsps.Inc(s.label(), string(ep), strconv.Itoa(status))
			done = true
		case errSkip:
			status = http.StatusFailedDependency
			glog.V(2).Infof("operation %s was skipped", ep)
			err = nil
			done = true
		default:
			errs.Inc(s.label(), string(ep))
			if s.cfg.IgnoreErrors {
				left := deadline.Sub(time.Now())
				glog.Warningf("%s: op %v failed after %v (will retry for %v more): %v", s.cfg.LogCfg.Prefix, ep, period, left, err)
			} else {
				done = true
			}
		}

		s.mu.Unlock()

		if err != nil && time.Now().After(deadline) {
			glog.Warningf("%s: gave up retrying failed op %v after %v, returning last err: %v", s.cfg.LogCfg.Prefix, ep, s.cfg.MaxRetryDuration, err)
			done = true
		}
	}
	return err
}

// HammerCTLog performs load/stress operations according to given config.
func HammerCTLog(cfg HammerConfig) error {
	s, err := newHammerState(&cfg)
	if err != nil {
		return err
	}
	ctx := context.Background()
	ticker := time.NewTicker(cfg.EmitInterval)

	go func(c <-chan time.Time) {
		for range c {
			glog.Info(s.String())
		}
	}(ticker.C)

	for count := uint64(1); count < cfg.Operations; count++ {
		if err := s.retryOneOp(ctx); err != nil {
			return err
		}
	}
	glog.Infof("%s: completed %d operations on log", cfg.LogCfg.Prefix, cfg.Operations)
	ticker.Stop()

	return nil
}
