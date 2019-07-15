package merkle

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"github.com/stretchr/testify/assert"
	"hash"
	"testing"
)

type HashCountDecorator struct {
	Hash  hash.Hash
	Count *int
}

func (decor HashCountDecorator) Write(p []byte) (n int, err error) {
	return decor.Hash.Write(p)
}

func (decor HashCountDecorator) Sum(b []byte) []byte {
	*decor.Count = *decor.Count + 1
	return decor.Hash.Sum(b)
}

func (decor HashCountDecorator) BlockSize() int {
	return decor.Hash.BlockSize()
}

func (decor HashCountDecorator) Size() int {
	return decor.Hash.Size()
}

func (decor HashCountDecorator) Reset() {
	decor.Hash.Reset()
}

func NewHashCountDecorator(h hash.Hash, count *int) HashCountDecorator {
	return HashCountDecorator{Hash: h, Count: count}
}

func TestBigFullEmptyLeavesCache(t *testing.T) {
	//2^20 empty leaves
	items := [][]byte{[]byte{}}
	for i := 0; i < 20; i++ {
		items = append(items, items...)
	}

	leafHashCount := 0
	nonLeafHashCount := 0
	hash := md5.New()
	decoratedLeafHash := NewHashCountDecorator(hash, &leafHashCount)
	decoratedNonLeafHash := NewHashCountDecorator(hash, &nonLeafHashCount)

	tree, err := NewSMTWithTwoHashFuncs(decoratedLeafHash, decoratedNonLeafHash)
	assert.Nil(t, err)
	err = tree.GenerateByTwoHashFunc(items)
	assert.Nil(t, err)

	assert.Equal(t, 20, nonLeafHashCount)
	assert.Equal(t, 1, leafHashCount)

	assert.Equal(t, 20, len(tree.Nodes))
}

func TestCacheFullEmptyLeaves(t *testing.T) {
	//16 empty leaves
	items := [][]byte{[]byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}}

	leafHashCount := 0
	nonLeafHashCount := 0
	hash := md5.New()
	decoratedLeafHash := NewHashCountDecorator(hash, &leafHashCount)
	decoratedNonLeafHash := NewHashCountDecorator(hash, &nonLeafHashCount)
	tree, err := NewSMTWithTwoHashFuncs(decoratedLeafHash, decoratedNonLeafHash)
	assert.Nil(t, err)
	err = tree.GenerateByTwoHashFunc(items)
	assert.Nil(t, err)
	//four levels
	assert.Equal(t, 4, nonLeafHashCount)

	assert.Equal(t, 1, leafHashCount)

	expectedRoot := []byte{211, 106, 3, 253, 238, 164, 19, 12, 143, 166, 236, 114, 118, 192, 223, 97}
	assert.Equal(t, bytes.Equal(tree.GetRoot(), expectedRoot), true)

	assert.Equal(t, 4, len(tree.Nodes))
}

func TestCacheWithSomeEmptyLeaves(t *testing.T) {
	//13 empty leaves
	items := [][]byte{[]byte("alpha1"), []byte("alpha2"), []byte("alpha3"), []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}}

	leafHashCount := 0
	nonLeafHashCount := 0
	hash := md5.New()
	decoratedLeafHash := NewHashCountDecorator(hash, &leafHashCount)
	decoratedNonLeafHash := NewHashCountDecorator(hash, &nonLeafHashCount)
	tree, err := NewSMTWithTwoHashFuncs(decoratedLeafHash, decoratedNonLeafHash)
	assert.Nil(t, err)
	err = tree.GenerateByTwoHashFunc(items)
	assert.Nil(t, err)

	assert.Equal(t, 3+2+2+1, nonLeafHashCount)
	assert.Equal(t, 4, leafHashCount)
	fmt.Printf("nodes map size %d\n", len(tree.Nodes))
	fmt.Printf("nodes map is %v\n", tree.Nodes)
	expectedRoot := []byte{70, 192, 54, 135, 85, 97, 23, 149, 170, 117, 239, 21, 118, 153, 76, 134}
	assert.Equal(t, bytes.Equal(tree.GetRoot(), expectedRoot), true)
	assert.Equal(t, 8+4, len(tree.Nodes))
}

func TestCacheWithoutEmptyLeaves(t *testing.T) {

	items := [][]byte{[]byte("alpha1"), []byte("alpha2"), []byte("alpha3"), []byte("alpha4"), []byte("alpha5"), []byte("alpha6"), []byte("alpha7"), []byte("alpha8"), []byte("alpha9"), []byte("alpha10"), []byte("alpha11"), []byte("alpha12"), []byte("alpha13"), []byte("alpha14"), []byte("alpha15"), []byte("alpha16")}

	leafHashCount := 0
	nonLeafHashCount := 0
	hash := md5.New()
	decoratedLeafHash := NewHashCountDecorator(hash, &leafHashCount)
	decoratedNonLeafHash := NewHashCountDecorator(hash, &nonLeafHashCount)
	tree, err := NewSMTWithTwoHashFuncs(decoratedLeafHash, decoratedNonLeafHash)
	assert.Nil(t, err)
	err = tree.GenerateByTwoHashFunc(items)
	assert.Nil(t, err)

	assert.Equal(t, 8+4+2+1, nonLeafHashCount)
	assert.Equal(t, 16+1, leafHashCount)
	expectedRoot := []byte{128, 114, 175, 140, 59, 253, 14, 136, 26, 157, 15, 64, 61, 36, 68, 36}
	assert.Equal(t, bytes.Equal(tree.GetRoot(), expectedRoot), true)
	assert.Equal(t, 15+16, len(tree.Nodes))
}

func TestCacheWithoutLeafHashFunc(t *testing.T) {

	//leafHashCount := 0
	nonLeafHashCount := 0
	hash := md5.New()
	//decoratedLeafHash := NewHashCountDecorator(hash, &leafHashCount)
	decoratedNonLeafHash := NewHashCountDecorator(hash, &nonLeafHashCount)

	emptyLeafHash, err := emptyLeafHash(hash)
	assert.Nil(t, err)

	//13 empty leaves
	items := [][]byte{[]byte("alpha1"), []byte("alpha2"), []byte("alpha3"), emptyLeafHash, emptyLeafHash, emptyLeafHash, emptyLeafHash, emptyLeafHash, emptyLeafHash, emptyLeafHash, emptyLeafHash, emptyLeafHash, emptyLeafHash, emptyLeafHash, emptyLeafHash, emptyLeafHash}

	tree, err := NewSMTWithNonLeafHashAndEmptyLeafHashValue(emptyLeafHash, decoratedNonLeafHash)
	assert.Nil(t, err)
	err = tree.GenerateByTwoHashFunc(items)
	assert.Nil(t, err)

	assert.Equal(t, 3+2+2+1, nonLeafHashCount)
	//assert.Equal(t, 0, leafHashCount)
	//	expectedRoot := []byte{128, 114, 175, 140, 59, 253, 14, 136, 26, 157, 15, 64, 61, 36, 68, 36}
	//	assert.Equal(t, bytes.Equal(tree.GetRoot(), expectedRoot), true)
	fmt.Printf("Nodes %v\n", tree.Nodes)
	assert.Equal(t, 8+4, len(tree.Nodes))
}
