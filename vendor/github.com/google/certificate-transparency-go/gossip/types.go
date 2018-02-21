// Copyright 2015 Google Inc. All Rights Reserved.
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

// Package gossip holds code for spreading CT log information via a gossip
// protocol.
package gossip

import (
	ct "github.com/google/certificate-transparency-go"
)

// STHVersion reflects the STH Version field in RFC6862[-bis]
type STHVersion int

// STHVersion constants
const (
	STHVersion0 = 0
	STHVersion1 = 1
)

// SCTFeedbackEntry represents a single piece of SCT feedback.
type SCTFeedbackEntry struct {
	X509Chain []string `json:"x509_chain"`
	SCTData   []string `json:"sct_data"`
}

// SCTFeedback represents a collection of SCTFeedback which a client might send together.
type SCTFeedback struct {
	Feedback []SCTFeedbackEntry `json:"sct_feedback"`
}

// STHPollination represents a collection of STH pollination entries which a client might send together.
type STHPollination struct {
	STHs []ct.SignedTreeHead `json:"sths"`
}
