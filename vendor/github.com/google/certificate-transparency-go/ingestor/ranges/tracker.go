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

// Package ranges provides tools to track the completeness of a range composed of a number of sub-ranges which may be added in any order.
package ranges

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// Tracker tracks a range of integer indices which may be split into a set
// of non-overlapping sub-ranges.  The Tracker is defined over a range
// [start, end] with 0 <= start <= end.
//
// As sub-ranges are added to the Tracker, the range being tracked
// progresses towards becoming complete.  When the set of sub-ranges that have
// been added form a contiguous range equal to [start, end] the Tracker is
// complete.
//
// If the set of sub-ranges that have been added include a sub-range whose first
// index is 'start' the Tracker is considered partially complete.  Then,
// PartiallyCompleteUpto() can be used to determine the last index in a sub-
// range contiguous to the start.
//
// Examples:
// 1. Tracker for [0, 99]: sub-ranges [10, 19] and [30, 39] added
//    -> neither complete nor partially complete.
// 2. Tracker for [0, 99]: sub-ranges [0, 19] and [30, 39] added
//    -> not complete, but partially complete upto 19.
// 3. Tracker for [0, 99]: sub-ranges [0, 19] and [20, 39] added
//    -> not complete, but partially complete upto 39.
// 4. Tracker for [0, 99]: sub-ranges [50, 99] and [0, 49] added
//    -> complete.
type Tracker struct {
	start, end int64         // the extent of the range being tracked [start, end]
	wm         watermarks    // the low, mid and high water marks (see below)
	subRanges  subRangeSlice // the ranges recorded so far - kept sorted by subRange.first
	startTime  time.Time     // timestamp recorded when Tracker created
}

// watermarks encapsulates a set of three watermarks that are calculated when
// subranges are added.  The watermarks are used to determine the completion
// state of the tracker.  They are defined as follows:
// * the 'low-water' mark indicates the lowest value in any sub-range added;
// * the 'mid-water' mark indicates the high point in the lowest contiguous set
//   of sub-ranges if we have a sub-range whose first index is 'start'; if not,
//   it is set to -1.
// * the 'high-water' mark indicates the highest value in any sub-range added.
// When (lo, hi) == (start, end) of the expected range, and hi == mid, then the
// full extent of the expected range has been recorded.
type watermarks struct {
	lo, mid, hi int64
}

func (wm *watermarks) update(start int64, srs subRangeSlice) {
	lo, mid, hi := int64(math.MaxInt64), int64(-1), int64(-1)
	for _, sr := range srs {
		if sr.first < lo {
			lo = sr.first
		}
		if sr.last > hi {
			hi = sr.last
		}
	}
	if lo == start {
		// The range is partially complete as we have a subrange located at the
		// range start.  The mid watermark is the highest entry in a contiguous
		// subrange.
		nextLo := lo
		for _, sr := range srs {
			if sr.first == nextLo {
				mid = sr.last
				nextLo = mid + 1
			}
		}
	}
	wm.lo, wm.mid, wm.hi = lo, mid, hi
}

func (wm watermarks) String() string {
	return fmt.Sprintf("<lo %d, mid %d, hi %d>", wm.lo, wm.mid, wm.hi)
}

// subRange is defined as a pair of indices [first, last]
type subRange struct {
	first, last int64
}

// String conforms with fmt.Stringer for subRange.
func (sr subRange) String() string {
	return fmt.Sprintf("<first %d, last %d>", sr.first, sr.last)
}

type subRangeSlice []subRange

// Len conforms with sort.Interface for subRangeSlice
func (srs subRangeSlice) Len() int {
	return len(srs)
}

// Less conforms with sort.Interface for subRangeSlice
func (srs subRangeSlice) Less(i, j int) bool {
	return srs[i].first < srs[j].first
}

// Swap conforms with sort.Interface for subRangeSlice
func (srs subRangeSlice) Swap(i, j int) {
	srs[i].first, srs[j].first = srs[j].first, srs[i].first
	srs[i].last, srs[j].last = srs[j].last, srs[i].last
}

// timeNow may be replaced in tests.
var timeNow = time.Now

// NewTracker returns a Tracker for the range [start, end].
func NewTracker(start, end int64) (*Tracker, error) {
	if start > end {
		return nil, fmt.Errorf("want start <= end, got [start %d, end %d]", start, end)
	}
	if start < 0 {
		return nil, fmt.Errorf("want start >= 0, got %d]", start)
	}
	return &Tracker{
		start:     start,
		end:       end,
		wm:        watermarks{lo: -1, mid: -1, hi: -1},
		startTime: timeNow(),
	}, nil
}

// AddSubRange records a sub-range.  As sub-ranges are recorded, the low/mid/high watermarks are
// adjusted.
func (rt *Tracker) AddSubRange(first, last int64) error {
	if last < first {
		return fmt.Errorf("subrange [%d, %d] should have last > first", first, last)
	}
	if first < rt.start || last > rt.end {
		return fmt.Errorf("subrange [%d, %d] may not lie outside [%d, %d]", first, last, rt.start, rt.end)
	}
	// Check that [first, last] doesn't overlap any already-added subranges.
	for _, sr := range rt.subRanges {
		if (sr.first <= first && first <= sr.last) || (sr.first <= last && last <= sr.last) {
			return fmt.Errorf("trying to add overlapping subrange [%d, %d] which collides with [%d, %d]",
				first, last, sr.first, sr.last)
		}
	}

	rt.subRanges = append(rt.subRanges, subRange{first: first, last: last})
	sort.Sort(rt.subRanges)
	rt.wm.update(rt.start, rt.subRanges)
	return nil
}

// IsComplete returns true if the union of recorded sub-ranges equals the expected range.
func (rt *Tracker) IsComplete() bool {
	return rt.IsPartiallyComplete() && rt.wm.mid == rt.wm.hi && rt.wm.hi == rt.end
}

// IsPartiallyComplete returns true if a sub-range has been recorded whose first entry is located at the start of the expected range.
func (rt *Tracker) IsPartiallyComplete() bool {
	return rt.wm.mid >= 0
}

// PartiallyCompleteUpto returns the last entry of a set of contiguous recorded
// subranges that begins at the Tracker's start, or -1 if there are no
// subranges that satisfy this.
func (rt *Tracker) PartiallyCompleteUpto() int64 {
	return rt.wm.mid
}

func (rt *Tracker) progressSummary() string {
	switch {
	case rt.IsComplete():
		return "100% complete"
	case !rt.IsPartiallyComplete():
		return "0% complete"
	}
	fractionComplete := float32(rt.wm.mid+1-rt.start) / float32(rt.end-rt.start)
	elapsed := float32(timeNow().Sub(rt.startTime))
	remain := elapsed/fractionComplete - elapsed
	return fmt.Sprintf("%2.1f%% complete, done in %v", 100.0*fractionComplete, time.Duration(remain))
}

// String returns a printable representation of the Tracker.
func (rt *Tracker) String() string {
	return fmt.Sprintf("<expected range [start %d, end %d] watermarks %v #subranges %d %s>",
		rt.start, rt.end, rt.wm, len(rt.subRanges), rt.progressSummary())
}

// DebugString returns a verbose printable representation of the Tracker, including details of all added subranges, for debug use.
func (rt *Tracker) DebugString() string {
	srs := make([]string, 0, len(rt.subRanges))
	for _, sr := range rt.subRanges {
		srs = append(srs, sr.String())
	}

	return fmt.Sprintf("<expected range [start %d, end %d] watermarks %v subranges [%v] %s>",
		rt.start, rt.end, rt.wm, strings.Join(srs, " "), rt.progressSummary())
}
