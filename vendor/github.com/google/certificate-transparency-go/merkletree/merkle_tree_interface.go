// Copyright 2014 Google Inc. All Rights Reserved.
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

// Package merkletree holds code to manipulate Merkle trees.
package merkletree

// MerkleTreeInterface represents the common interface for basic MerkleTree functions.
type MerkleTreeInterface interface { // nolint: golint
	// LeafCount returns the number of leaves in the tree
	LeafCount() uint64

	// LevelCount returns the number of levels in the tree
	LevelCount() uint64

	// AddLeaf adds the hash of |leaf| to the tree and returns the newly added
	// leaf index
	AddLeaf(leaf []byte) uint64

	// LeafHash returns the hash of the leaf at index |leaf| or a non-nil error.
	LeafHash(leaf uint64) ([]byte, error)

	// CurrentRoot returns the current root hash of the merkle tree.
	CurrentRoot() ([]byte, error)
}

// FullMerkleTreeInterface extends MerkleTreeInterface to the full range of
// operations that only a non-compact tree representation can implement.
type FullMerkleTreeInterface interface {
	MerkleTreeInterface

	// RootAtSnapshot returns the root hash at the tree size |snapshot|
	// which must be <= than the current tree size.
	RootAtSnapshot(snapshot uint64) ([]byte, error)

	// PathToCurrentRoot returns the Merkle path (or inclusion proof) from the
	// leaf hash at index |leaf| to the current root.
	PathToCurrentRoot(leaf uint64) ([]byte, error)

	// SnapshotConsistency returns a consistency proof between the two tree
	// sizes specified in |snapshot1| and |snapshot2|.
	SnapshotConsistency(snapshot1, snapshot2 uint64) ([]byte, error)
}
