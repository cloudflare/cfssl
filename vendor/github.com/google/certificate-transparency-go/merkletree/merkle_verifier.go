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

import (
	"bytes"
	"errors"
	"fmt"
)

// RootMismatchError occurs when an inclusion proof fails.
type RootMismatchError struct {
	ExpectedRoot   []byte
	CalculatedRoot []byte
}

func (e RootMismatchError) Error() string {
	return fmt.Sprintf("calculated root:\n%v\n does not match expected root:\n%v", e.CalculatedRoot, e.ExpectedRoot)
}

// MerkleVerifier is a class which knows how to verify merkle inclusion and consistency proofs.
type MerkleVerifier struct {
	treeHasher *TreeHasher
}

// NewMerkleVerifier returns a new MerkleVerifier for a tree based on the passed in hasher.
func NewMerkleVerifier(h HasherFunc) MerkleVerifier {
	return MerkleVerifier{
		treeHasher: NewTreeHasher(h),
	}
}

// VerifyInclusionProof verifies the correctness of the proof given the passed in information about the tree and leaf.
func (m MerkleVerifier) VerifyInclusionProof(leafIndex, treeSize int64, proof [][]byte, root []byte, leaf []byte) error {
	calcRoot, err := m.RootFromInclusionProof(leafIndex, treeSize, proof, leaf)
	if err != nil {
		return err
	}
	if len(calcRoot) == 0 {
		return errors.New("calculated empty root")
	}
	if !bytes.Equal(calcRoot, root) {
		return RootMismatchError{CalculatedRoot: calcRoot, ExpectedRoot: root}
	}
	return nil
}

// VerifyInclusionProofByHash verifies the correctness of the proof given tree and leaf hash.
func (m MerkleVerifier) VerifyInclusionProofByHash(leafIndex, treeSize int64, proof [][]byte, root []byte, leafHash []byte) error {
	calcRoot, err := m.RootFromInclusionProofAndHash(leafIndex, treeSize, proof, leafHash)
	if err != nil {
		return err
	}
	if len(calcRoot) == 0 {
		return errors.New("calculated empty root")
	}
	if !bytes.Equal(calcRoot, root) {
		return RootMismatchError{CalculatedRoot: calcRoot, ExpectedRoot: root}
	}
	return nil
}

// RootFromInclusionProof calculates the expected tree root given the proof and leaf.
// leafIndex starts at 0. treeSize starts at 1.
func (m MerkleVerifier) RootFromInclusionProof(leafIndex, treeSize int64, proof [][]byte, leaf []byte) ([]byte, error) {
	leafHash := m.treeHasher.HashLeaf(leaf)
	return m.RootFromInclusionProofAndHash(leafIndex, treeSize, proof, leafHash)
}

// RootFromInclusionProofAndHash calculates the expected tree root given the proof and leaf hash.
// leafIndex starts at 0. treeSize starts at 1.
func (m MerkleVerifier) RootFromInclusionProofAndHash(leafIndex, treeSize int64, proof [][]byte, leafHash []byte) ([]byte, error) {
	if leafIndex >= treeSize {
		return nil, fmt.Errorf("leafIndex %d > treeSize %d", leafIndex, treeSize)
	}
	if leafIndex < 0 || treeSize < 1 {
		return nil, errors.New("leafIndex < 0 or treeSize < 1")
	}

	nodeIndex := leafIndex
	lastNode := treeSize - 1
	nodeHash := leafHash
	proofIndex := 0

	for lastNode > 0 {
		if proofIndex == len(proof) {
			return nil, fmt.Errorf("insuficient number of proof components (%d) for treeSize %d", len(proof), treeSize)
		}
		if isRightChild(nodeIndex) {
			nodeHash = m.treeHasher.HashChildren(proof[proofIndex], nodeHash)
			proofIndex++
		} else if nodeIndex < lastNode {
			nodeHash = m.treeHasher.HashChildren(nodeHash, proof[proofIndex])
			proofIndex++
		} else {
			// the sibling does not exist and the parent is a dummy copy; do nothing.
		}
		nodeIndex = parent(nodeIndex)
		lastNode = parent(lastNode)
	}
	if proofIndex != len(proof) {
		return nil, fmt.Errorf("invalid proof, expected %d components, but have %d", proofIndex, len(proof))
	}
	return nodeHash, nil
}

// VerifyConsistencyProof checks that the passed in consistency proof is valid between the passed in tree snapshots.
func (m MerkleVerifier) VerifyConsistencyProof(snapshot1, snapshot2 int64, root1, root2 []byte, proof [][]byte) error {
	if snapshot1 > snapshot2 {
		return fmt.Errorf("snapshot1 (%d) > snapshot2 (%d)", snapshot1, snapshot2)
	}
	if snapshot1 == snapshot2 {
		if !bytes.Equal(root1, root2) {
			return fmt.Errorf("root1:\n%v\ndoes not match root2:\n%v", root1, root2)
		}
		if len(proof) > 0 {
			return fmt.Errorf("root1 and root2 match, but proof is non-empty")
		}
		// proof ok
		return nil
	}

	if snapshot1 == 0 {
		// Any snapshot greater than 0 is consistent with snapshot 0.
		if len(proof) > 0 {
			return fmt.Errorf("expected empty proof, but provided proof has %d components", len(proof))
		}
		return nil
	}

	if len(proof) == 0 {
		return errors.New("empty proof")
	}

	node := snapshot1 - 1
	lastNode := snapshot2 - 1
	proofIndex := 0

	for isRightChild(node) {
		node = parent(node)
		lastNode = parent(lastNode)
	}

	var node1Hash []byte
	var node2Hash []byte

	if node > 0 {
		node1Hash = proof[proofIndex]
		node2Hash = proof[proofIndex]
		proofIndex++
	} else {
		// The tree at snapshot1 was balanced, nothing to verify for root1.
		node1Hash = root1
		node2Hash = root1
	}

	for node > 0 {
		if proofIndex == len(proof) {
			return errors.New("insufficient number of proof components")
		}

		if isRightChild(node) {
			node1Hash = m.treeHasher.HashChildren(proof[proofIndex], node1Hash)
			node2Hash = m.treeHasher.HashChildren(proof[proofIndex], node2Hash)
			proofIndex++
		} else if node < lastNode {
			// The sibling only exists in the later tree. The parent in the snapshot1 tree is a dummy copy.
			node2Hash = m.treeHasher.HashChildren(node2Hash, proof[proofIndex])
			proofIndex++
		} else {
			// Else the sibling does not exist in either tree. Do nothing.
		}

		node = parent(node)
		lastNode = parent(lastNode)
	}

	// Verify the first root.
	if !bytes.Equal(node1Hash, root1) {
		return fmt.Errorf("failed to verify root1:\n%v\ncalculated root of:\n%v\nfrom proof", root1, node1Hash)
	}

	for lastNode > 0 {
		if proofIndex == len(proof) {
			return errors.New("can't verify newer root; insufficient number of proof components")
		}

		node2Hash = m.treeHasher.HashChildren(node2Hash, proof[proofIndex])
		proofIndex++
		lastNode = parent(lastNode)
	}

	// Verify the second root.
	if !bytes.Equal(node2Hash, root2) {
		return fmt.Errorf("failed to verify root2:\n%v\ncalculated root of:\n%v\nfrom proof", root2, node2Hash)
	}
	if proofIndex != len(proof) {
		return errors.New("proof has too many components")
	}

	// proof ok
	return nil
}

func parent(leafIndex int64) int64 {
	return leafIndex >> 1
}

func isRightChild(leafIndex int64) bool {
	return leafIndex&1 == 1
}
