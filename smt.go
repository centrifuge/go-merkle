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
	RootNode      SMTNode
	LeafHash      hash.Hash
	NonLeafHash   hash.Hash
	EmptyLeafHash []byte

	cachedAllLevelsHashOfEmptyLeaves    [][]byte
	cachedAllLevelsHashHexOfEmptyLeaves []string
	treeHeight                          uint
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
	hashHex := fmt.Sprintf("%x", emptyLeafHash)

	smt := SMT{Nodes: map[string]SMTNode{}, cachedAllLevelsHashOfEmptyLeaves: [][]byte{emptyLeafHash}, cachedAllLevelsHashHexOfEmptyLeaves: []string{hashHex}, EmptyLeafHash: emptyLeafHash, LeafHash: leafHash, NonLeafHash: nonLeafHash}
	return smt, nil
}

type SMTNode interface {
	GetHash(tree *SMT) []byte
	GetLeftNode(tree *SMT) SMTNode
	GetRightNode(tree *SMT) SMTNode
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

func (node LeafNode) GetLeftNode(tree *SMT) SMTNode {
	return nil
}

func (node LeafNode) GetRightNode(tree *SMT) SMTNode {
	return nil
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

func (node NodeWithAtLeastOneNonEmptyLeafInLeftChild) GetLeftNode(tree *SMT) SMTNode {
	return tree.Nodes[node.LeftChildHashHexString]
}

func (node NodeWithAtLeastOneNonEmptyLeafInLeftChild) GetRightNode(tree *SMT) SMTNode {
	return tree.Nodes[node.RightChildHashHexString]
}

type NodeWithAllEmptyLeaf struct {
	Index int
}

func NewNodeWithAllEmptyLeaf(index int) SMTNode {
	return NodeWithAllEmptyLeaf{Index: index}
}

func (node NodeWithAllEmptyLeaf) GetHash(tree *SMT) []byte {
	return tree.cachedAllLevelsHashOfEmptyLeaves[node.Index]
}

func (node NodeWithAllEmptyLeaf) GetLeftNode(tree *SMT) SMTNode {
	hashHex := tree.cachedAllLevelsHashHexOfEmptyLeaves[node.Index+1]
	return tree.Nodes[hashHex]
}

func (node NodeWithAllEmptyLeaf) GetRightNode(tree *SMT) SMTNode {
	return node.GetLeftNode(tree)
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

func (self *SMT) Generate(blocks [][]byte) error {
	if !isPowerOfTwo(uint64(len(blocks))) {
		return errors.New("Leaves number of SMT tree should be power of 2")
	}
	self.treeHeight = uint(logBaseTwo(uint64(len(blocks))) + 1)
	root, err := self.GenerateSMT(0, len(blocks)-1, blocks)
	if err == nil {
		self.Root = root
		rootHashHex := fmt.Sprintf("%x", root)
		self.RootNode = self.Nodes[rootHashHex]
	}
	return err
}

func (self *SMT) GetRoot() []byte {
	return self.Root
}

type ProofNode struct {
	Hash []byte
	Left bool
}

func (self *SMT) GetMerkelProof(leafNo uint) []ProofNode {
	proofs := []ProofNode{}
	parentNode := self.RootNode

	for i := self.treeHeight - 1; i > 0; i-- {
		mask := uint(1) << (i - 1)
		bit := mask & leafNo
		var sibleHash []byte
		left := false
		if bit > 0 {
			sibleHash = parentNode.GetLeftNode(self).GetHash(self)
			left = true
			parentNode = parentNode.GetRightNode(self)
		} else {
			sibleHash = parentNode.GetRightNode(self).GetHash(self)
			parentNode = parentNode.GetLeftNode(self)
		}
		proofNode := ProofNode{Hash: sibleHash, Left: left}
		proofs = append([]ProofNode{proofNode}, proofs...)

	}
	return proofs
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
	self.cachedAllLevelsHashOfEmptyLeaves = append(self.cachedAllLevelsHashOfEmptyLeaves, hash)
	hashHex := fmt.Sprintf("%x", hash)
	self.Nodes[hashHex] = NewNodeWithAllEmptyLeaf(len(self.cachedAllLevelsHashOfEmptyLeaves) - 1)
	self.cachedAllLevelsHashHexOfEmptyLeaves = append(self.cachedAllLevelsHashHexOfEmptyLeaves, hashHex)
}

func (self *SMT) ComputeEmptyLeavesSubTreeHash(leavesNumber int) ([]byte, error) {
	if 2 == leavesNumber {
		hash := self.EmptyLeafHash
		var err error
		hash, err = self.parentHash(hash, hash)
		if err != nil {
			return []byte{}, err
		}
		self.addNodeWithAllEmptyLeaf(hash)
		return hash, nil
	}

	levels := logBaseTwo(uint64(leavesNumber))
	if self.cachedAllLevelsHashOfEmptyLeaves != nil && uint64(len(self.cachedAllLevelsHashOfEmptyLeaves)) > levels {
		return self.cachedAllLevelsHashOfEmptyLeaves[levels], nil
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

func (self *SMT) addNodeWithAtLeastOneNonEmptyLeafInLeftChild(hash []byte, leftHash []byte, rightHash []byte) SMTNode {
	leftHashHex := fmt.Sprintf("%x", leftHash)
	rightHashHex := fmt.Sprintf("%x", rightHash)
	hashHex := fmt.Sprintf("%x", hash)
	smtNode := NewNodeWithAtLeastOneNonEmptyLeafInLeftChild(hash, leftHashHex, rightHashHex)
	self.Nodes[hashHex] = smtNode
	return smtNode
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
