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

// TreeOptions configures tree behavior
type TreeOptions struct {
	// EnableHashSorting modifies the tree's hash behavior to sort the hashes before concatenating them
	// to calculate the parent hash. This removes the capability of proving the position in the tree but
	// simplifies the proof format by removing the need to specify left/right.
	EnableHashSorting bool

	// DisableHashLeaves determines whether leaf nodes should be hashed or not. By disabling this behavior,
	// you can use a different hash function for leaves or generate a tree that contains already hashed
	// values.
	DisableHashLeaves bool
}

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
	Nodes []Node
	// Points to each level in the node. The first level contains the root node
	Levels [][]Node
	// Any particular behavior changing option
	Options TreeOptions
}

func NewTreeWithOpts(options TreeOptions) Tree {
	tree := NewTree()
	tree.Options = options
	return tree
}

func NewTree() Tree {
	return Tree{Nodes: nil, Levels: nil}
}

// Returns a slice of the leaf nodes in the tree, if available, else nil
func (self *Tree) Leaves() []Node {
	if self.Levels == nil {
		return nil
	} else {
		return self.Levels[len(self.Levels)-1]
	}
}

// Returns the root node of the tree, if available, else nil
func (self *Tree) Root() *Node {
	if self.Nodes == nil {
		return nil
	} else {
		return &self.Levels[0][0]
	}
}

// Returns all nodes at a given height, where height 1 returns a 1-element
// slice containing the root node, and a height of tree.Height() returns
// the leaves
func (self *Tree) GetNodesAtHeight(h uint64) []Node {
	if self.Levels == nil || h == 0 || h > uint64(len(self.Levels)) {
		return nil
	} else {
		return self.Levels[h-1]
	}
}

// Returns the height of this tree
func (self *Tree) Height() uint64 {
	return uint64(len(self.Levels))
}

func (self *Tree) Generate(blocks [][]byte, hashf hash.Hash) error {
	return self.GenerateByTwoHashFunc(blocks, hashf, hashf)
}

// Generates the tree nodes by using different hash funtions between internal and leaf node
func (self *Tree) GenerateByTwoHashFunc(blocks [][]byte, nonLeafHash hash.Hash, leafHash hash.Hash) error {
	blockCount := uint64(len(blocks))
	if blockCount == 0 {
		return errors.New("Empty tree")
	}
	height, nodeCount := CalculateHeightAndNodeCount(blockCount)
	levels := make([][]Node, height)
	nodes := make([]Node, nodeCount)

	// Create the leaf nodes
	for i, block := range blocks {
		var node Node
		var err error
		if self.Options.DisableHashLeaves {
			node, err = NewNode(nil, block)
		} else {
			node, err = NewNode(leafHash, block)
		}
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
		wrote, err := self.generateNodeLevel(below, current, nonLeafHash)
		if err != nil {
			return err
		}
		levels[h-1] = current[:wrote]
		current = current[wrote:]
	}

	self.Nodes = nodes
	self.Levels = levels
	return nil
}

// Creates all the non-leaf nodes for a certain height. The number of nodes
// is calculated to be 1/2 the number of nodes in the lower rung.  The newly
// created nodes will reference their Left and Right children.
// Returns the number of nodes added to current
func (self *Tree) generateNodeLevel(below []Node, current []Node,
	h hash.Hash) (uint64, error) {
	h.Reset()

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
		node, err := self.generateNode(below[ileft].Hash, rightHash, h)
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

func (self *Tree) generateNode(left, right []byte, h hash.Hash) (Node, error) {
	if right == nil {
		data := make([]byte, len(left))
		copy(data, left)
		return Node{Hash: data}, nil
	}

	data := make([]byte, len(left)+len(right))
	if self.Options.EnableHashSorting && bytes.Compare(left, right) > 0 {
		copy(data[:len(right)], right)
		copy(data[len(right):], left)
	} else {
		copy(data[:len(left)], left)
		copy(data[len(left):], right)
	}

	return NewNode(h, data)
}

// Returns the height and number of nodes in an unbalanced binary tree given
// number of leaves
func CalculateHeightAndNodeCount(leaves uint64) (height, nodeCount uint64) {
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
