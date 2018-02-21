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

// Package util provides general utility functions for the CT personality.
package util

import "time"

// TimeSource can provide the current time, or be replaced by a mock in tests to return
// specific values.
type TimeSource interface {
	// Now returns the current time in real implementations or a suitable value in others
	Now() time.Time
}

// SystemTimeSource provides the current system local time
type SystemTimeSource struct{}

// Now returns the true current local time.
func (s SystemTimeSource) Now() time.Time {
	return time.Now()
}

// FixedTimeSource provides a fixed time for use in tests.
// It should not be used in production code.
type FixedTimeSource struct {
	fakeTime time.Time
}

// NewFixedTimeSource creates a FixedTimeSource instance
func NewFixedTimeSource(t time.Time) *FixedTimeSource {
	return &FixedTimeSource{fakeTime: t}
}

// Now returns the time value this instance contains
func (f *FixedTimeSource) Now() time.Time {
	return f.fakeTime
}
