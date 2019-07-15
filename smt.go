/* Copyright 2013 Steve Leonard <sleonard76@gmail.com>. All rights reserved.
Use of this source code is governed by the MIT license that can be found
in the LICENSE file.
*/

/* Package merkle is a fixed merkle tree implementation */
package merkle

import (
	"bytes"
	"errors"
	"fmt"
	"hash"
)

type SMT struct {
	Nodes         map[string]SMTNode
	Root          []byte
	LeafHash      hash.Hash
	NonLeafHash   hash.Hash
	EmptyLeafHash []byte

	CachedAllLevelsHashOfEmptyLeaves    [][]byte
	CachedAllLevelsHashHexOfEmptyLeaves []string
	CachedLevels                        int
}

func NewSMTWithTwoHashFuncs(leafHash hash.Hash, nonLeafHash hash.Hash) (SMT, error) {
	emptyLeafHash, err := emptyLeafHash(leafHash)
	if err != nil {
		return SMT{}, err
	}
	return newSMT(leafHash, nonLeafHash, emptyLeafHash)
}

func NewSMTWithNonLeafHashAndEmptyLeafHashValue(emptyLeafHash []byte, nonLeafHash hash.Hash) (SMT, error) {
	return newSMT(nil, nonLeafHash, emptyLeafHash)
}

func newSMT(leafHash hash.Hash, nonLeafHash hash.Hash, emptyLeafHash []byte) (SMT, error) {
	return SMT{Nodes: map[string]SMTNode{}, CachedAllLevelsHashOfEmptyLeaves: [][]byte{}, CachedAllLevelsHashHexOfEmptyLeaves: []string{}, EmptyLeafHash: emptyLeafHash, LeafHash: leafHash, NonLeafHash: nonLeafHash}, nil
}

type SMTNode interface {
	GetHash(tree *SMT) []byte
	GetLeftHashHex(tree *SMT) string
	GetRightHashHex(tree *SMT) string
}

type LeafNode struct {
	Hash []byte
}

func NewLeafNode(hash []byte) SMTNode {
	return LeafNode{Hash: hash}
}

func (node LeafNode) GetHash(tree *SMT) []byte {
	return node.Hash
}

func (node LeafNode) GetLeftHashHex(tree *SMT) string {
	return ""
}

func (node LeafNode) GetRightHashHex(tree *SMT) string {
	return ""
}

type NodeWithAtLeastOneNonEmptyLeafInLeftChild struct {
	Hash                    []byte
	LeftChildHashHexString  string
	RightChildHashHexString string
}

func NewNodeWithAtLeastOneNonEmptyLeafInLeftChild(hash []byte, left string, right string) SMTNode {
	return NodeWithAtLeastOneNonEmptyLeafInLeftChild{Hash: hash, LeftChildHashHexString: left, RightChildHashHexString: right}
}

func (node NodeWithAtLeastOneNonEmptyLeafInLeftChild) GetHash(tree *SMT) []byte {
	return node.Hash
}

func (node NodeWithAtLeastOneNonEmptyLeafInLeftChild) GetLeftHashHex(tree *SMT) string {
	return node.LeftChildHashHexString
}

func (node NodeWithAtLeastOneNonEmptyLeafInLeftChild) GetRightHashHex(tree *SMT) string {
	return node.RightChildHashHexString
}

type NodeWithAllEmptyLeaf struct {
	Index int
}

func NewNodeWithAllEmptyLeaf(index int) SMTNode {
	return NodeWithAllEmptyLeaf{Index: index}
}
func (node NodeWithAllEmptyLeaf) GetHash(tree *SMT) []byte {
	return tree.CachedAllLevelsHashOfEmptyLeaves[node.Index]
}

func (node NodeWithAllEmptyLeaf) GetLeftHashHex(tree *SMT) string {
	return tree.CachedAllLevelsHashHexOfEmptyLeaves[node.Index+1]
}

func (node NodeWithAllEmptyLeaf) GetRightHashHex(tree *SMT) string {
	return tree.CachedAllLevelsHashHexOfEmptyLeaves[node.Index+1]
}

func emptyLeafHash(h hash.Hash) ([]byte, error) {
	defer h.Reset()
	_, err := h.Write([]byte{})
	if err != nil {
		return []byte{}, err
	}
	hash := h.Sum(nil)
	return hash, nil
}

func (self *SMT) GenerateByTwoHashFunc(blocks [][]byte) error {
	if !isPowerOfTwo(uint64(len(blocks))) {
		return errors.New("Leaves number of SMT tree should be power of 2")
	}
	root, err := self.GenerateSMT(0, len(blocks)-1, blocks)
	fmt.Printf("root is    %v\n\n", root)
	if err == nil {
		self.Root = root
	}
	return err
}

func (self *SMT) GetRoot() []byte {
	return self.Root
}

func (self *SMT) parentHash(item1 []byte, item2 []byte) ([]byte, error) {
	hash := self.NonLeafHash
	defer hash.Reset()
	combinedItem := make([]byte, len(item1)+len(item2))
	copy(combinedItem[:len(item1)], item1)
	copy(combinedItem[len(item1):], item2)

	_, err := hash.Write(combinedItem[:])
	if err != nil {
		return []byte{}, err
	}
	return hash.Sum(nil), nil
}

func (self *SMT) isEmptyLeaf(item []byte) bool {
	if self.LeafHash == nil {
		return bytes.Equal(item, self.EmptyLeafHash)
	} else {
		return bytes.Equal(item, []byte{})
	}
}

func (self *SMT) addLeafNode(leafHash []byte) {
	leafHashHex := fmt.Sprintf("%x", leafHash)
	self.Nodes[leafHashHex] = NewLeafNode(leafHash)
}

func (self *SMT) leafHash(leaf []byte) ([]byte, error) {
	if self.LeafHash == nil {
		self.addLeafNode(leaf)
		return leaf, nil
	}

	if self.isEmptyLeaf(leaf) {
		self.addLeafNode(self.EmptyLeafHash)
		return self.EmptyLeafHash, nil
	}
	leafHashFunc := self.LeafHash
	defer leafHashFunc.Reset()

	_, err := leafHashFunc.Write(leaf[:])
	if err != nil {
		return []byte{}, err
	}
	leafHash := leafHashFunc.Sum(nil)
	self.addLeafNode(leafHash)
	return leafHash, nil
}

func (self *SMT) addNodeWithAllEmptyLeaf(hash []byte) {
	self.CachedAllLevelsHashOfEmptyLeaves = append(self.CachedAllLevelsHashOfEmptyLeaves, hash)
	self.CachedLevels = self.CachedLevels + 1
	hashHex := fmt.Sprintf("%x", hash)
	self.Nodes[hashHex] = NewNodeWithAllEmptyLeaf(len(self.CachedAllLevelsHashOfEmptyLeaves))
	self.CachedAllLevelsHashHexOfEmptyLeaves = append(self.CachedAllLevelsHashHexOfEmptyLeaves, hashHex)
}

func (self *SMT) ComputeEmptyLeavesSubTreeHash(leavesNumber int) ([]byte, error) {
	if 2 == leavesNumber {
		hash := self.EmptyLeafHash
		var err error

		if self.CachedAllLevelsHashOfEmptyLeaves != nil && len(self.CachedAllLevelsHashOfEmptyLeaves) > 0 {
			hash = self.CachedAllLevelsHashOfEmptyLeaves[0]
		} else {
			hash, err = self.parentHash(hash, hash)
			if err != nil {
				return []byte{}, err
			}
			self.addNodeWithAllEmptyLeaf(hash)
		}
		return hash, nil
	}

	levels := logBaseTwo(uint64(leavesNumber)) - 1
	if self.CachedAllLevelsHashOfEmptyLeaves != nil && uint64(len(self.CachedAllLevelsHashOfEmptyLeaves)) > levels {
		return self.CachedAllLevelsHashOfEmptyLeaves[levels], nil
	}

	nextLevelHash, err := self.ComputeEmptyLeavesSubTreeHash(leavesNumber / 2)
	if err != nil {
		return []byte{}, nil
	}
	combinedHash, err := self.parentHash(nextLevelHash, nextLevelHash)
	if err != nil {
		return []byte{}, nil
	}

	self.addNodeWithAllEmptyLeaf(combinedHash)

	return combinedHash, nil
}

func (self *SMT) addNodeWithAtLeastOneNonEmptyLeafInLeftChild(hash []byte, leftHash []byte, rightHash []byte) {
	leftHashHex := fmt.Sprintf("%x", leftHash)
	rightHashHex := fmt.Sprintf("%x", rightHash)
	hashHex := fmt.Sprintf("%x", hash)
	self.Nodes[hashHex] = NewNodeWithAtLeastOneNonEmptyLeafInLeftChild(hash, leftHashHex, rightHashHex)
}

func (self *SMT) GenerateSMT(start int, end int, blocks [][]byte) ([]byte, error) {

	totalEle := (end - start) + 1
	if self.isEmptyLeaf(blocks[start]) {
		return self.ComputeEmptyLeavesSubTreeHash(totalEle)
	}

	if totalEle == 2 {
		left, err := self.leafHash(blocks[start])
		if err != nil {
			return []byte{}, nil
		}
		right, err := self.leafHash(blocks[start+1])
		if err != nil {
			return []byte{}, nil
		}
		hash, err := self.parentHash(left, right)
		if err != nil {
			return []byte{}, nil
		}
		self.addNodeWithAtLeastOneNonEmptyLeafInLeftChild(hash, left, right)
		return hash, err
	}

	leftStart := start
	leftEnd := start + (totalEle / 2) - 1
	rightStart := leftEnd + 1
	rightEnd := end

	var rightHash []byte
	var err error
	if self.isEmptyLeaf(blocks[rightStart]) {
		rightHash, err = self.ComputeEmptyLeavesSubTreeHash(rightEnd - rightStart + 1)
	} else {
		rightHash, err = self.GenerateSMT(rightStart, rightEnd, blocks)
	}
	if err != nil {
		return []byte{}, err
	}

	leftHash, err := self.GenerateSMT(leftStart, leftEnd, blocks)
	if err != nil {
		return []byte{}, err
	}

	hash, err := self.parentHash(leftHash, rightHash)
	if err != nil {
		return []byte{}, nil
	}
	self.addNodeWithAtLeastOneNonEmptyLeafInLeftChild(hash, leftHash, rightHash)
	return hash, err
}
