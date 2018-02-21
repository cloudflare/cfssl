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
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/google/certificate-transparency-go/trillian/ctfe/configpb"
	"github.com/google/certificate-transparency-go/trillian/util"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/trillian"
	"github.com/google/trillian/crypto"
	"github.com/google/trillian/crypto/keys"
	"github.com/google/trillian/monitoring"
)

// LogConfigFromFile creates a slice of LogConfig options from the given
// filename, which should contain text-protobuf encoded configuration data.
func LogConfigFromFile(filename string) ([]*configpb.LogConfig, error) {
	cfgText, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var cfg configpb.LogConfigSet
	if err := proto.UnmarshalText(string(cfgText), &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse log config: %v", err)
	}

	if len(cfg.Config) == 0 {
		return nil, errors.New("empty log config found")
	}
	return cfg.Config, nil
}

// MultiLogConfigFromFile creates a LogMultiConfig proto from the given
// filename, which should contain text-protobuf encoded configuration data.
// Does not do full validation of the config but checks that it is non empty.
func MultiLogConfigFromFile(filename string) (*configpb.LogMultiConfig, error) {
	cfgText, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var cfg configpb.LogMultiConfig
	if err := proto.UnmarshalText(string(cfgText), &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse multi-backend log config: %v", err)
	}

	if len(cfg.LogConfigs.GetConfig()) == 0 || len(cfg.Backends.GetBackend()) == 0 {
		return nil, errors.New("config is missing backends and/or log configs")
	}
	return &cfg, nil
}

var stringToKeyUsage = map[string]x509.ExtKeyUsage{
	"Any":                        x509.ExtKeyUsageAny,
	"ServerAuth":                 x509.ExtKeyUsageServerAuth,
	"ClientAuth":                 x509.ExtKeyUsageClientAuth,
	"CodeSigning":                x509.ExtKeyUsageCodeSigning,
	"EmailProtection":            x509.ExtKeyUsageEmailProtection,
	"IPSECEndSystem":             x509.ExtKeyUsageIPSECEndSystem,
	"IPSECTunnel":                x509.ExtKeyUsageIPSECTunnel,
	"IPSECUser":                  x509.ExtKeyUsageIPSECUser,
	"TimeStamping":               x509.ExtKeyUsageTimeStamping,
	"OCSPSigning":                x509.ExtKeyUsageOCSPSigning,
	"MicrosoftServerGatedCrypto": x509.ExtKeyUsageMicrosoftServerGatedCrypto,
	"NetscapeServerGatedCrypto":  x509.ExtKeyUsageNetscapeServerGatedCrypto,
}

// InstanceOptions describes the options for a log instance.
type InstanceOptions struct {
	Deadline      time.Duration
	MetricFactory monitoring.MetricFactory
	// ErrorMapper converts an error from an RPC request to an HTTP status, plus
	// a boolean to indicate whether the conversion succeeded.
	ErrorMapper func(error) (int, bool)
	RequestLog  RequestLog
}

// SetUpInstance sets up a log instance that uses the specified client to communicate
// with the Trillian RPC back end.
func SetUpInstance(ctx context.Context, client trillian.TrillianLogClient, cfg *configpb.LogConfig, opts InstanceOptions) (*PathHandlers, error) {
	// Check config validity.
	if len(cfg.RootsPemFile) == 0 {
		return nil, errors.New("need to specify RootsPemFile")
	}
	if cfg.PrivateKey == nil {
		return nil, errors.New("need to specify PrivateKey")
	}

	// Load the trusted roots
	roots := NewPEMCertPool()
	for _, pemFile := range cfg.RootsPemFile {
		if err := roots.AppendCertsFromPEMFile(pemFile); err != nil {
			return nil, fmt.Errorf("failed to read trusted roots: %v", err)
		}
	}

	// Load the private key for this log.
	var keyProto ptypes.DynamicAny
	if err := ptypes.UnmarshalAny(cfg.PrivateKey, &keyProto); err != nil {
		return nil, fmt.Errorf("failed to unmarshal cfg.PrivateKey: %v", err)
	}

	key, err := keys.NewSigner(ctx, keyProto.Message)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %v", err)
	}
	signer := crypto.NewSHA256Signer(key)

	var keyUsages []x509.ExtKeyUsage
	if len(cfg.ExtKeyUsages) > 0 {
		for _, kuStr := range cfg.ExtKeyUsages {
			if ku, present := stringToKeyUsage[kuStr]; present {
				keyUsages = append(keyUsages, ku)
			} else {
				return nil, fmt.Errorf("unknown extended key usage: %s", kuStr)
			}
		}
	} else {
		keyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}

	var naStart, naLimit *time.Time

	if cfg.NotAfterStart != nil {
		t, err := ptypes.Timestamp(cfg.NotAfterStart)
		if err != nil {
			return nil, fmt.Errorf("invalid not_after_start: %v", err)
		}
		naStart = &t
	}
	if cfg.NotAfterLimit != nil {
		t, err := ptypes.Timestamp(cfg.NotAfterLimit)
		if err != nil {
			return nil, fmt.Errorf("invalid not_after_limit: %v", err)
		}
		naLimit = &t
	}

	validationOpts := CertValidationOpts{
		trustedRoots:  roots,
		rejectExpired: cfg.RejectExpired,
		notAfterStart: naStart,
		notAfterLimit: naLimit,
		acceptOnlyCA:  cfg.AcceptOnlyCa,
		extKeyUsages:  keyUsages,
	}
	// Create and register the handlers using the RPC client we just set up.
	logCtx := NewLogContext(cfg.LogId,
		cfg.Prefix,
		validationOpts,
		client,
		signer,
		opts,
		new(util.SystemTimeSource))

	handlers := logCtx.Handlers(cfg.Prefix)
	return &handlers, nil
}

// ValidateLogMultiConfig checks that a config is valid for use with multiple
// backend log servers. The rules applied are:
//
// 1. The backend set must define a set of log backends with distinct
// (non empty) names and non empty backend specs.
// 2. The backend specs must all be distinct.
// 3. The log configs must all specify a log backend and each must be one of
// those defined in the backend set.
// 4. If NotBeforeStart or NotBeforeLimit are set for a log then these fields
// must be valid timestamp protos. If both are set then NotBeforeLimit must
// not be before NotBeforeStart.
// 5. The prefixes of configured logs must all be distinct and must not be
// empty.
// 6. The set of tree ids for each configured backend must be distinct.
func ValidateLogMultiConfig(cfg *configpb.LogMultiConfig) (map[string]*configpb.LogBackend, error) {
	// Check the backends have unique non empty names and build the map.
	backendMap := make(map[string]*configpb.LogBackend)
	bSpecMap := make(map[string]bool)
	for _, backend := range cfg.Backends.Backend {
		if len(backend.Name) == 0 {
			return nil, fmt.Errorf("empty backend name: %v", backend)
		}
		if len(backend.BackendSpec) == 0 {
			return nil, fmt.Errorf("empty backend_spec for backend: %v", backend)
		}
		if _, ok := backendMap[backend.Name]; ok {
			return nil, fmt.Errorf("duplicate backend name: %v", backend)
		}
		if ok := bSpecMap[backend.BackendSpec]; ok {
			return nil, fmt.Errorf("duplicate backend spec: %v", backend)
		}
		backendMap[backend.Name] = backend
		bSpecMap[backend.BackendSpec] = true
	}

	// Check that logs all reference a defined backend and there are no duplicate
	// or empty prefixes. Apply other LogConfig specific checks.
	logNameMap := make(map[string]bool)
	logIDMap := make(map[string]bool)
	for _, logCfg := range cfg.LogConfigs.Config {
		if len(logCfg.Prefix) == 0 {
			return nil, fmt.Errorf("log config: empty prefix: %v", logCfg)
		}
		if logNameMap[logCfg.Prefix] {
			return nil, fmt.Errorf("log config: duplicate prefix: %s: %v", logCfg.Prefix, logCfg)
		}
		if _, ok := backendMap[logCfg.LogBackendName]; !ok {
			return nil, fmt.Errorf("log config: references undefined backend: %s: %v", logCfg.LogBackendName, logCfg)
		}
		logNameMap[logCfg.Prefix] = true
		logIDKey := fmt.Sprintf("%s-%d", logCfg.LogBackendName, logCfg.LogId)
		if ok := logIDMap[logIDKey]; ok {
			return nil, fmt.Errorf("log config: dup tree id: %d for: %v", logCfg.LogId, logCfg)
		}
		var err error
		var tStart time.Time
		start := logCfg.GetNotAfterStart()
		if start != nil {
			tStart, err = ptypes.Timestamp(start)
			if err != nil {
				return nil, fmt.Errorf("log_config: invalid start timestamp %v for: %v", err, logCfg)
			}
		}
		var tLimit time.Time
		limit := logCfg.GetNotAfterLimit()
		if limit != nil {
			tLimit, err = ptypes.Timestamp(limit)
			if err != nil {
				return nil, fmt.Errorf("log_config: invalid limit timestamp %v for: %v", err, logCfg)
			}
		}
		if start != nil && limit != nil && tLimit.Before(tStart) {
			return nil, fmt.Errorf("log_config: limit before start for: %v", logCfg)
		}
		logIDMap[logIDKey] = true
	}

	return backendMap, nil
}

// ToMultiLogConfig creates a multi backend config proto from the data
// loaded from a single-backend configuration file. All the log configs
// reference a default backend spec as provided.
func ToMultiLogConfig(cfg []*configpb.LogConfig, beSpec string) *configpb.LogMultiConfig {
	defaultBackend := &configpb.LogBackend{Name: "default", BackendSpec: beSpec}
	for _, c := range cfg {
		c.LogBackendName = defaultBackend.Name
	}
	return &configpb.LogMultiConfig{
		LogConfigs: &configpb.LogConfigSet{Config: cfg},
		Backends:   &configpb.LogBackendSet{Backend: []*configpb.LogBackend{defaultBackend}},
	}
}
