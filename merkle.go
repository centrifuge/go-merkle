/* Copyright 2013 Steve Leonard <sleonard76@gmail.com>. All rights reserved.
Use of this source code is governed by the MIT license that can be found
in the LICENSE file.
*/

/* Package merkle is a fixed merkle tree implementation */
package merkle

import (
	"bytes"
	"errors"
	"hash"
)

// Node in the merkle tree
type Node struct {
	Hash  []byte
	Left  *Node
	Right *Node
}

// NewNode creates a node given a hash function and data to hash. If the hash function is nil, the data
// will be added without being hashed.
func NewNode(h hash.Hash, block []byte) (Node, error) {
	if h == nil {
		return Node{Hash: block}, nil
	}
	if block == nil {
		return Node{}, nil
	}
	defer h.Reset()
	_, err := h.Write(block[:])
	if err != nil {
		return Node{}, err
	}
	return Node{Hash: h.Sum(nil)}, nil
}

// Tree contains all nodes
type Tree struct {
	// All nodes, linear
	nodes []Node
	// Points to each level in the node. The first level contains the root node
	levels [][]Node

	enableHashSorting bool
	hashFunc          hash.Hash
}

func NewTreeWithHashSortingEnable(hashFunc hash.Hash) *Tree {
	return &Tree{nodes: nil, levels: nil, enableHashSorting: true, hashFunc: hashFunc}
}

func NewTree(hashFunc hash.Hash) *Tree {
	return &Tree{nodes: nil, levels: nil, hashFunc: hashFunc}
}

func (self *Tree) RootHash() []byte {
	if self.nodes == nil {
		return nil
	} else {
		return self.levels[0][0].Hash
	}
}

// Generates the tree nodes by using different hash funtions between internal and leaf node
func (self *Tree) Generate(blocks [][]byte, totalLeavesSize int) error {
	return self.generate(blocks)
}
func (self *Tree) generate(blocks [][]byte) error {
	blockCount := uint64(len(blocks))
	if blockCount == 0 {
		return errors.New("Empty tree")
	}
	height, nodeCount := calculateHeightAndNodeCount(blockCount)
	levels := make([][]Node, height)
	nodes := make([]Node, nodeCount)

	// Create the leaf nodes
	for i, block := range blocks {
		node, err := NewNode(nil, block)
		if err != nil {
			return err
		}
		nodes[i] = node
	}
	levels[height-1] = nodes[:len(blocks)]

	// Create each node level
	current := nodes[len(blocks):]
	h := height - 1
	for ; h > 0; h-- {
		below := levels[h]
		wrote, err := self.generateNodeLevel(below, current)
		if err != nil {
			return err
		}
		levels[h-1] = current[:wrote]
		current = current[wrote:]
	}

	self.nodes = nodes
	self.levels = levels
	return nil
}

func (self *Tree) GetMerkleProof(leafIndex uint) ([]ProofNode, error) {
	leafCount := len(self.leaves())
	if leafCount == 0 {
		return nil, errors.New("SMT tree is not filled")
	}

	if leafIndex >= uint(leafCount) {
		return nil, errors.New("node index is too big for node count")
	}
	height, _ := calculateHeightAndNodeCount(uint64(leafCount))
	index := 0
	lastNodeInLevel := uint64(leafCount) - 1
	offset := uint64(0)
	nodes := []ProofNode{}

	for level := height - 1; level > 0; level-- {
		// only add hash if this isn't an odd end
		if !(uint64(leafIndex) == lastNodeInLevel && (lastNodeInLevel+1)%2 == 1) {
			if leafIndex%2 == 0 {
				nodes = append(nodes, ProofNode{Left: false, Hash: self.nodes[offset+uint64(leafIndex)+1].Hash})

			} else {
				nodes = append(nodes, ProofNode{Left: true, Hash: self.nodes[offset+uint64(leafIndex)-1].Hash})
			}
			index++
		}
		leafIndex = leafIndex / 2
		offset += lastNodeInLevel + 1
		lastNodeInLevel = (lastNodeInLevel+1)/2 + (lastNodeInLevel+1)%2 - 1
	}
	return nodes, nil

}

// Following are non public

// Returns a slice of the leaf nodes in the tree, if available, else nil
func (self *Tree) leaves() []Node {
	if self.levels == nil {
		return nil
	} else {
		return self.levels[len(self.levels)-1]
	}
}

// Returns the root node of the tree, if available, else nil
func (self *Tree) root() *Node {
	if self.nodes == nil {
		return nil
	} else {
		return &self.levels[0][0]
	}
}

// Returns all nodes at a given height, where height 1 returns a 1-element
// slice containing the root node, and a height of tree.Height() returns
// the leaves

func (self *Tree) getNodesAtHeight(h uint64) []Node {
	if self.levels == nil || h == 0 || h > uint64(len(self.levels)) {
		return nil
	} else {
		return self.levels[h-1]
	}
}

// Returns the height of this tree
func (self *Tree) height() uint64 {
	return uint64(len(self.levels))
}

// Creates all the non-leaf nodes for a certain height. The number of nodes
// is calculated to be 1/2 the number of nodes in the lower rung.  The newly
// created nodes will reference their Left and Right children.
// Returns the number of nodes added to current
func (self *Tree) generateNodeLevel(below []Node, current []Node) (uint64, error) {
	//	self.nonLeafHashFunc.Reset()

	end := (len(below) + (len(below) % 2)) / 2
	for i := 0; i < end; i++ {
		// Concatenate the two children hashes and hash them, if both are
		// available, otherwise reuse the hash from the lone left node
		ileft := 2 * i
		iright := 2*i + 1
		left := &below[ileft]
		var right *Node = nil
		var rightHash []byte
		if len(below) > iright {
			right = &below[iright]
			rightHash = right.Hash
		}
		node, err := self.generateNode(below[ileft].Hash, rightHash)
		if err != nil {
			return 0, err
		}
		// Point the new node to its children and save
		node.Left = left
		node.Right = right
		current[i] = node

	}
	return uint64(end), nil
}

func (self *Tree) generateNode(left, right []byte) (Node, error) {
	if right == nil {
		data := make([]byte, len(left))
		copy(data, left)
		return Node{Hash: data}, nil
	}

	data := make([]byte, len(left)+len(right))
	if self.enableHashSorting && bytes.Compare(left, right) > 0 {
		copy(data[:len(right)], right)
		copy(data[len(right):], left)
	} else {
		copy(data[:len(left)], left)
		copy(data[len(left):], right)
	}

	return NewNode(self.hashFunc, data)
}

// Returns the height and number of nodes in an unbalanced binary tree given
// number of leaves
func calculateHeightAndNodeCount(leaves uint64) (height, nodeCount uint64) {
	height = calculateTreeHeight(leaves)
	nodeCount = calculateNodeCount(height, leaves)
	return
}

// Calculates the number of nodes in a binary tree unbalanced strictly on
// the right side.  Height is assumed to be equal to
// calculateTreeHeight(size)
func calculateNodeCount(height, size uint64) uint64 {
	if isPowerOfTwo(size) {
		return 2*size - 1
	}
	count := size
	prev := size
	i := uint64(1)
	for ; i < height; i++ {
		next := (prev + (prev % 2)) / 2
		count += next
		prev = next
	}
	return count
}

// Returns the height of a full, complete binary tree given nodeCount nodes
func calculateTreeHeight(nodeCount uint64) uint64 {
	if nodeCount == 0 {
		return 0
	} else {
		return logBaseTwo(nextPowerOfTwo(nodeCount)) + 1
	}
}
