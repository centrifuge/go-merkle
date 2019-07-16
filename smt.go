package merkle

import (
	"bytes"
	"errors"
	"hash"
)

type Hash []byte

type SMT struct {
	nodesWithoutEmptyLeavesSubTree [][]Hash
	leafHash                       hash.Hash
	nonLeafHash                    hash.Hash
	emptyLeafHash                  []byte

	levelsUpHashOfEmptyLeaves []Hash
	treeHeight                uint
	noOfNonEmptyLeaves        int
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

func (self *SMT) RootHash() []byte {
	if self.noOfNonEmptyLeaves == 0 {
		return self.levelsUpHashOfEmptyLeaves[len(self.levelsUpHashOfEmptyLeaves)-1]
	}
	return self.nodesWithoutEmptyLeavesSubTree[self.treeHeight-1][0]
}

func (self *SMT) buildLeavesNodes(nonEmptyLeaves [][]byte) error {
	hashes := []Hash{}
	counts := len(nonEmptyLeaves)
	for i := 0; i < counts; i++ {
		hash, err := self.leafHashFunc(nonEmptyLeaves[i])
		if err != nil {
			return err
		}
		hashes = append(hashes, hash)
	}

	self.nodesWithoutEmptyLeavesSubTree = append(self.nodesWithoutEmptyLeavesSubTree, hashes)

	return nil
}

func (self *SMT) buildAllLevelNodes(nonEmptyLeaves [][]byte) error {
	err := self.buildLeavesNodes(nonEmptyLeaves)
	if err != nil {
		return err
	}
	for i := self.treeHeight; i > 1; i-- {
		err := self.buildInternalOneLevelNodes(i - 1)
		if err != nil {
			return err
		}
	}
	return nil
}

func (self *SMT) buildInternalOneLevelNodes(levelsNo uint) error {
	lastLevelNodesHash := self.nodesWithoutEmptyLeavesSubTree[self.treeHeight-1-levelsNo]
	counts := len(lastLevelNodesHash)
	hashes := []Hash{}
	for i := 0; i < counts/2; i++ {
		hash, err := self.parentHash(lastLevelNodesHash[2*i], lastLevelNodesHash[2*i+1])
		if err != nil {
			return err
		}
		hashes = append(hashes, hash)
	}
	if counts%2 != 0 {
		siblingEmptyTreeHash := self.levelsUpHashOfEmptyLeaves[self.treeHeight-1-levelsNo]
		hash, err := self.parentHash(lastLevelNodesHash[counts-1], siblingEmptyTreeHash)
		if err != nil {
			return err
		}
		hashes = append(hashes, hash)
	}
	self.nodesWithoutEmptyLeavesSubTree = append(self.nodesWithoutEmptyLeavesSubTree, hashes)
	return nil
}

func (self *SMT) Generate(nonEmptyLeaves [][]byte, totalSize uint64) error {
	if !isPowerOfTwo(totalSize) {
		return errors.New("Leaves number of SMT tree should be power of 2")
	}
	if uint64(len(nonEmptyLeaves)) > totalSize {
		return errors.New("NonEmptyLeaves is bigger than totalSize ")
	}
	self.treeHeight = uint(logBaseTwo(totalSize) + 1)
	self.noOfNonEmptyLeaves = len(nonEmptyLeaves)
	noOfEmtpyLeaves := totalSize - uint64(len(nonEmptyLeaves))

	maxEmtySubTreeHeight := 0
	for i := noOfEmtpyLeaves; i > 0; i = i >> 1 {
		maxEmtySubTreeHeight++
	}
	err := self.computeEmptyLeavesSubTreeHash(maxEmtySubTreeHeight)
	if err != nil {
		return err
	}
	return self.buildAllLevelNodes(nonEmptyLeaves)
}

type ProofNode struct {
	Hash []byte
	Left bool
}

func (self *SMT) proofNodeAt(index int, level int) ProofNode {
	hashes := self.nodesWithoutEmptyLeavesSubTree[int(self.treeHeight)-level-1]
	var hash Hash
	left := false
	if index%2 == 1 {
		left = true
	}

	if left {
		hash = hashes[index-1]
	} else {
		if len(hashes)-1 < index+1 {
			hash = self.levelsUpHashOfEmptyLeaves[level+1]
		} else {
			hash = hashes[index+1]
		}
	}

	return ProofNode{Hash: hash, Left: left}
}

func (self *SMT) GetMerkelProof(leafNo uint) []ProofNode {
	proofs := []ProofNode{}
	level := int(self.treeHeight - 1)
	index := leafNo
	for i := level; i > 0; i-- {
		proofNode := self.proofNodeAt(int(index), int(i))
		proofs = append(proofs, proofNode)
		index = index / 2
	}
	return proofs
}

func newSMT(leafHash hash.Hash, nonLeafHash hash.Hash, emptyLeafHash []byte) (SMT, error) {
	smt := SMT{nodesWithoutEmptyLeavesSubTree: [][]Hash{}, levelsUpHashOfEmptyLeaves: []Hash{emptyLeafHash}, emptyLeafHash: emptyLeafHash, leafHash: leafHash, nonLeafHash: nonLeafHash}
	return smt, nil
}

func (self *SMT) computeEmptyLeavesSubTreeHash(maxHeight int) error {
	lastLevelHash := self.emptyLeafHash
	var err error
	for i := 1; i < maxHeight; i++ {
		lastLevelHash, err = self.parentHash(lastLevelHash, lastLevelHash)
		if err != nil {
			return err
		}
		self.levelsUpHashOfEmptyLeaves = append(self.levelsUpHashOfEmptyLeaves, lastLevelHash)
	}
	return nil
}

func (self *SMT) isEmptyLeaf(item []byte) bool {
	if self.leafHash == nil {
		return bytes.Equal(item, self.emptyLeafHash)
	} else {
		return bytes.Equal(item, []byte{})
	}
}

func (self *SMT) leafHashFunc(leaf []byte) ([]byte, error) {
	if self.leafHash == nil {
		return leaf, nil
	}

	leafHashFunc := self.leafHash
	defer leafHashFunc.Reset()

	_, err := leafHashFunc.Write(leaf[:])
	if err != nil {
		return []byte{}, err
	}
	leafHash := leafHashFunc.Sum(nil)
	return leafHash, nil
}

func (self *SMT) parentHash(item1 []byte, item2 []byte) ([]byte, error) {
	hash := self.nonLeafHash
	defer hash.Reset()

	_, err := hash.Write(item1)
	if err != nil {
		return []byte{}, err
	}
	_, err = hash.Write(item2)
	if err != nil {
		return []byte{}, err
	}
	return hash.Sum(nil), nil
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
