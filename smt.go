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
	hashFunc              hash.Hash
	emptyHash             []byte
	emptyTreeRootHash     []Hash
	treeHeight            uint
	countOfNonEmptyLeaves int
	filled                bool
}

func NewSMT(emptyHash []byte, hashFunc hash.Hash) SMT {
	return SMT{fullNodes: [][]Hash{}, emptyTreeRootHash: []Hash{emptyHash}, emptyHash: emptyHash, hashFunc: hashFunc}
}

func (self *SMT) RootHash() ([]byte, error) {
	if !self.filled {
		return nil, errors.New("SMT tree is not filled")
	}
	if self.countOfNonEmptyLeaves == 0 {
		return self.emptyTreeRootHash[len(self.emptyTreeRootHash)-1], nil
	}
	return self.fullNodes[self.treeHeight-1][0], nil
}

func (self *SMT) Generate(leaves [][]byte, totalSize uint64) error {
	if !isPowerOfTwo(totalSize) {
		return errors.New("Leaves number of SMT tree should be power of 2")
	}
	count := len(leaves)
	if uint64(count) > totalSize {
		return errors.New("NonEmptyLeaves is bigger than totalSize")
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

	hashes := []Hash{}
	for i := 0; i < count; i++ {
		hashes = append(hashes, leaves[i])
	}
	self.fullNodes = append(self.fullNodes, hashes)

	err = self.computeAllLevelNodes(leaves)
	if err != nil {
		return err
	}
	self.filled = true
	return nil
}

func (self *SMT) GetMerkleProof(leafNo uint) ([]ProofNode, error) {
	if !self.filled {
		return nil, errors.New("SMT tree is not filled")
	}

	proofs := []ProofNode{}
	level := int(self.treeHeight - 1)
	index := leafNo
	for i := level; i > 0; i-- {
		proofNode := self.proofNodeAt(int(index), int(i))
		proofs = append(proofs, proofNode)
		index = index / 2
	}
	return proofs, nil
}

//Following are non public function

func (self *SMT) computeEmptyLeavesSubTreeHash(maxHeight int) error {
	lastLevelHash := self.emptyHash
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

func (self *SMT) computeAllLevelNodes(leaves [][]byte) error {
	for i := self.treeHeight; i > 1; i-- {
		err := self.computeNodesAt(i - 1)
		if err != nil {
			return err
		}
	}
	return nil
}

func (self *SMT) computeNodesAt(level uint) error {
	lastLevelNodesHash := self.fullNodes[self.treeHeight-1-level]
	count := len(lastLevelNodesHash)
	hashes := []Hash{}
	countRoundToEven := (count / 2) * 2
	for i := 0; i < countRoundToEven; i += 2 {
		hash, err := self.parentHash(lastLevelNodesHash[i], lastLevelNodesHash[i+1])
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

	hashes := self.fullNodes[int(self.treeHeight)-1-level]
	var hash Hash
	left := false
	if index%2 == 1 {
		left = true
	}
	if left {
		hash = hashes[index-1]
	} else {
		if len(hashes)-1 < index+1 {
			hash = self.emptyTreeRootHash[int(self.treeHeight)-1-level]
		} else {
			hash = hashes[index+1]
		}
	}
	return ProofNode{Hash: hash, Left: left}
}

func (self *SMT) parentHash(item1 []byte, item2 []byte) ([]byte, error) {
	hash := self.hashFunc
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
