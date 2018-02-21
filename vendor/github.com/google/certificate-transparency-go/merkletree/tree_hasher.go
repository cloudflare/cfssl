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

package merkletree

const (
	// LeafPrefix is the domain separation prefix for leaf hashes.
	LeafPrefix = 0

	// NodePrefix is the domain separation prefix for internal tree nodes.
	NodePrefix = 1
)

// HasherFunc takes a slice of bytes and returns a cryptographic hash of those bytes.
type HasherFunc func([]byte) []byte

// TreeHasher performs the various hashing operations required when manipulating MerkleTrees.
type TreeHasher struct {
	hasher HasherFunc
}

// NewTreeHasher returns a new TreeHasher based on the passed in hash.
func NewTreeHasher(h HasherFunc) *TreeHasher {
	return &TreeHasher{
		hasher: h,
	}
}

// HashEmpty returns the hash of the empty string.
func (h TreeHasher) HashEmpty() []byte {
	return h.hasher([]byte{})
}

// HashLeaf returns the hash of the passed in leaf, after applying domain separation.
func (h TreeHasher) HashLeaf(leaf []byte) []byte {
	return h.hasher(append([]byte{LeafPrefix}, leaf...))

}

// HashChildren returns the merkle hash of the two passed in children.
func (h TreeHasher) HashChildren(left, right []byte) []byte {
	return h.hasher(append(append([]byte{NodePrefix}, left...), right...))
}
