/* Copyright 2019 Kevin Zhang <kevin.zhang0125@gmail.com>, Lucas Vogelsang <lucas@centrifuge.io>. All rights reserved.
Use of this source code is governed by the MIT license that can be found
in the LICENSE file.
*/

package merkle

type Hash []byte

type ProofNode struct {
	Hash []byte
	Left bool
}

type MerkleTree interface {
	Generate(leaves [][]byte, totalLeavesSize int) error
	RootHash() []byte
	GetMerkleProof(leafIndex uint) ([]ProofNode, error)
}
