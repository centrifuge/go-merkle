package merkle

import (
	"errors"
	"hash"
)

type Hash []byte

type ProofNode struct {
	Hash []byte
	Left bool
}

// A Sparse Merkle Tree which support all empty leaves lies in
type SMT struct {
	fullNodes             [][]Hash
	leafHashFunc          hash.Hash
	nonLeafHashFunc       hash.Hash
	emptyLeafHash         []byte
	emptyTreeRootHash     []Hash
	treeHeight            uint
	countOfNonEmptyLeaves int
}

func NewSMTWithTwoHashFuncs(leafHashFunc hash.Hash, nonLeafHashFunc hash.Hash) (SMT, error) {
	emptyLeafHash, err := emptyLeafHash(leafHashFunc)
	if err != nil {
		return SMT{}, err
	}
	return newSMT(leafHashFunc, nonLeafHashFunc, emptyLeafHash)
}

func NewSMTWithNonLeafHashAndEmptyLeafHashValue(emptyLeafHash []byte, nonLeafHashFunc hash.Hash) (SMT, error) {
	return newSMT(nil, nonLeafHashFunc, emptyLeafHash)
}

func (self *SMT) RootHash() []byte {
	if self.countOfNonEmptyLeaves == 0 {
		return self.emptyTreeRootHash[len(self.emptyTreeRootHash)-1]
	}
	return self.fullNodes[self.treeHeight-1][0]
}

func (self *SMT) Generate(leaves [][]byte, totalSize uint64) error {
	if !isPowerOfTwo(totalSize) {
		return errors.New("Leaves number of SMT tree should be power of 2")
	}
	if uint64(len(leaves)) > totalSize {
		return errors.New("NonEmptyLeaves is bigger than totalSize ")
	}
	self.treeHeight = uint(logBaseTwo(totalSize) + 1)
	self.countOfNonEmptyLeaves = len(leaves)

	noOfEmtpyLeaves := totalSize - uint64(len(leaves))
	maxEmtySubTreeHeight := 0
	for i := noOfEmtpyLeaves; i > 0; i = i >> 1 {
		maxEmtySubTreeHeight++
	}
	err := self.computeEmptyLeavesSubTreeHash(maxEmtySubTreeHeight)
	if err != nil {
		return err
	}
	return self.buildAllLevelNodes(leaves)
}

func (self *SMT) GetMerkleProof(leafNo uint) []ProofNode {
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

//Following are non public function
func newSMT(leafHashFunc hash.Hash, nonLeafHashFunc hash.Hash, emptyLeafHash []byte) (SMT, error) {
	smt := SMT{fullNodes: [][]Hash{}, emptyTreeRootHash: []Hash{emptyLeafHash}, emptyLeafHash: emptyLeafHash, leafHashFunc: leafHashFunc, nonLeafHashFunc: nonLeafHashFunc}
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
		self.emptyTreeRootHash = append(self.emptyTreeRootHash, lastLevelHash)
	}
	return nil
}

func (self *SMT) buildAllLevelNodes(leaves [][]byte) error {
	err := self.buildLeavesNodes(leaves)
	if err != nil {
		return err
	}
	for i := self.treeHeight; i > 1; i-- {
		err := self.computeNodesAt(i - 1)
		if err != nil {
			return err
		}
	}
	return nil
}

func (self *SMT) buildLeavesNodes(leaves [][]byte) error {
	hashes := []Hash{}
	count := len(leaves)
	for i := 0; i < count; i++ {
		hash, err := self.leafHash(leaves[i])
		if err != nil {
			return err
		}
		hashes = append(hashes, hash)
	}
	self.fullNodes = append(self.fullNodes, hashes)
	return nil
}

func (self *SMT) computeNodesAt(level uint) error {
	lastLevelNodesHash := self.fullNodes[self.treeHeight-1-level]
	count := len(lastLevelNodesHash)
	hashes := []Hash{}
	for i := 0; i < count/2; i++ {
		hash, err := self.parentHash(lastLevelNodesHash[2*i], lastLevelNodesHash[2*i+1])
		if err != nil {
			return err
		}
		hashes = append(hashes, hash)
	}
	if count%2 != 0 {
		siblingEmptyTreeHash := self.emptyTreeRootHash[self.treeHeight-1-level]
		hash, err := self.parentHash(lastLevelNodesHash[count-1], siblingEmptyTreeHash)
		if err != nil {
			return err
		}
		hashes = append(hashes, hash)
	}
	self.fullNodes = append(self.fullNodes, hashes)
	return nil
}

func (self *SMT) proofNodeAt(index int, level int) ProofNode {
	hashes := self.fullNodes[int(self.treeHeight)-level-1]
	var hash Hash
	left := false
	if index%2 == 1 {
		left = true
	}
	if left {
		hash = hashes[index-1]
	} else {
		if len(hashes)-1 < index+1 {
			hash = self.emptyTreeRootHash[level+1]
		} else {
			hash = hashes[index+1]
		}
	}
	return ProofNode{Hash: hash, Left: left}
}

func (self *SMT) leafHash(leaf []byte) ([]byte, error) {
	if self.leafHashFunc == nil {
		return leaf, nil
	}

	leafHashFunc := self.leafHashFunc
	defer leafHashFunc.Reset()

	_, err := leafHashFunc.Write(leaf[:])
	if err != nil {
		return []byte{}, err
	}
	leafHash := leafHashFunc.Sum(nil)
	return leafHash, nil
}

func (self *SMT) parentHash(item1 []byte, item2 []byte) ([]byte, error) {
	hash := self.nonLeafHashFunc
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
