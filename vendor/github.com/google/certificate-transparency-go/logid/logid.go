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

// Package logid provides a type and accompanying helpers for manipulating log IDs.
package logid

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
)

// LogID is a unique identifier for a CT Log derived from its public key as described by RFC6962
// sect. 3.2.  Since it is derived from a SHA-256 hash, its length is fixed at 32 bytes.
type LogID [sha256.Size]byte

// FromBytes returns a LogID copied from the supplied byte slice.
func FromBytes(bytes []byte) (LogID, error) {
	var logID LogID
	if len(bytes) != sha256.Size {
		return logID, fmt.Errorf("FromBytes(%x): want %d bytes, got %d", bytes, sha256.Size, len(bytes))
	}
	copy(logID[:], bytes)
	return logID, nil
}

// FromB64 returns a LogID from parsing the supplied base64-encoded Log ID.
func FromB64(logIDB64 string) (LogID, error) {
	buf, err := base64.StdEncoding.DecodeString(logIDB64)
	if err != nil {
		return LogID{}, err
	}
	return FromBytes(buf[:])
}

// FromB64OrDie returns a LogID from parsing supplied base64-encoded data that we assert is
// already well-formed, so it 'cannot fail'.
func FromB64OrDie(logIDB64 string) LogID {
	logID, err := FromB64(logIDB64)
	if err != nil {
		log.Fatalf("FromB64(%q): %v", logIDB64, err)
	}
	return logID
}

// FromPubKeyB64 takes a base64 encoded DER public key, and converts it into
// a LogID, as defined in RFC6962 - i.e. the SHA-256 hash of the base64 decoded
// bytes of the log's public key.
func FromPubKeyB64(pubKeyB64 string) (LogID, error) {
	pkBytes, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return LogID{}, fmt.Errorf("error decoding public key %q from base64: %s", pubKeyB64, err)
	}
	return LogID(sha256.Sum256(pkBytes)), nil
}

// FromPubKeyB64OrDie takes a base64 encoded DER public key, and converts it
// into a LogID, as defined in RFC6962 - i.e. the sha256 hash of the base64
// decoded bytes of the log's public key. This is for data that we assert is
// already well-formed, so it 'cannot fail'.
func FromPubKeyB64OrDie(pubKeyB64 string) LogID {
	logID, err := FromPubKeyB64(pubKeyB64)
	if err != nil {
		log.Fatalf("FromPubKeyB64(%q): %v", pubKeyB64, err)
	}
	return logID
}

// Bytes returns the raw bytes of the LogID, as a slice.
func (l LogID) Bytes() []byte {
	return l[:]
}

// String base64-encodes a LogID for ease of debugging.
func (l LogID) String() string {
	return fmt.Sprintf("logid:[%s]", base64.StdEncoding.EncodeToString(l.Bytes()))
}
