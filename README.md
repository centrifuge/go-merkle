go-merkle
=========
[![GoDoc](https://godoc.org/github.com/xsleonard/go-merkle?status.svg)](https://godoc.org/github.com/xsleonard/go-merkle)
[![Travis CI](https://api.travis-ci.org/xsleonard/go-merkle.svg?branch=master)](https://travis-ci.org/xsleonard/go-merkle)
[![codecov](https://codecov.io/gh/xsleonard/go-merkle/branch/master/graph/badge.svg)](https://codecov.io/gh/xsleonard/go-merkle)

This library implements a standard Merkle Tree in Go and also provides a sparse Merkle tree implementation. The SMT implementaiton only allows full leaves on the left and will arrange all empty leaves in rightmost positions. The total leaf count must be a power of 2.

Example Use
===========

```
package main

import (
    "crypto/md5"
    "fmt"
    "github.com/xsleonard/go-merkle"
    "io/ioutil"
)

func splitData(data []byte, size int) [][]byte {
    /* Splits data into an array of slices of len(size) */
    count := len(data) / size
    blocks := make([][]byte, 0, count)
    for i := 0; i < count; i++ {
        block := data[i*size : (i+1)*size]
        blocks = append(blocks, block)
    }
    if len(data)%size != 0 {
        blocks = append(blocks, data[len(blocks)*size:])
    }
    return blocks
}

func main() {
    // Grab some data to make the tree out of, and partition
    data, err := ioutil.ReadFile("testdata") // assume testdata exists
    if err != nil {
        fmt.Println(err)
        return
    }
    blocks := splitData(data, 32)

    // Create & generate the tree
    tree := merkle.NewTree(md5.New())
    // Create & generate the tree with sorted hashes
    // A tree with pair wise sorted hashes allows for a representation of proofs which are more space efficient
    // tree := merkle.NewTreeWithHashSortingEnable(md5.New())
    err = tree.Generate(blocks, 0)
    if err != nil {
        fmt.Println(err)
        return
    }

    proof, err := tree.GetMerkleProof(0)
        if err != nil {
        fmt.Println(err)
        return
    }

    fmt.Printf("Root Hash: %v\n", tree.RootHash())
    fmt.Prinff("Proof of first leaf: %v\n", proof)


    // Create & generate sparse tree
    hashFunc := md5.New()
    _, err := hashFunc.Write([]byte{})
    if err != nil {
        fmt.Println(err)
        return
    }
    emptyLeafHash := h.Sum(nil)
    tree := merkle.NewSMT(emptyLeafHash, md5.New())

    err = tree.Generate(blocks, 64)
    if err != nil {
        fmt.Println(err)
        return
    }

    proof, err := tree.GetMerkleProof(0)
        if err != nil {
        fmt.Println(err)
        return
    }

    fmt.Printf("Root Hash: %v\n", tree.RootHash())
    fmt.Prinff("Proof of first leaf: %v\n", proof)
}

```
