package merkle

import (
  "bytes"
	"crypto/md5"
  "hash"
	"testing"

	"github.com/stretchr/testify/assert"
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

func TestCacheFullEmptyLeaves(t *testing.T) {
	//16 empty leaves
	items := [][]byte{[]byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{},[]byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}}

	leafHashCount := 0
	nonLeafHashCount := 0
	hash := md5.New()
	decoratedLeafHash := NewHashCountDecorator(hash, &leafHashCount)
	decoratedNonLeafHash := NewHashCountDecorator(hash, &nonLeafHashCount)
	tree := NewSMT()
	err := tree.GenerateByTwoHashFunc(items, decoratedLeafHash, decoratedNonLeafHash)
	assert.Nil(t, err)
	//four levels
	assert.Equal(t, 4, nonLeafHashCount)

  assert.Equal(t, 1, leafHashCount)

  expectedRoot := []byte{211, 106, 3, 253, 238, 164, 19, 12, 143, 166, 236, 114, 118, 192, 223, 97}
  assert.Equal(t, bytes.Equal(tree.GetRoot(), expectedRoot), true)
}


func TestCacheWithSomeEmptyLeaves(t *testing.T) {
	//13 empty leaves
	items := [][]byte{[]byte("alpha1"), []byte("alpha2"), []byte("alpha3"), []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}}

	leafHashCount := 0
	nonLeafHashCount := 0
	hash := md5.New()
	decoratedLeafHash := NewHashCountDecorator(hash, &leafHashCount)
	decoratedNonLeafHash := NewHashCountDecorator(hash, &nonLeafHashCount)
	tree := NewSMT()
	err := tree.GenerateByTwoHashFunc(items, decoratedLeafHash, decoratedNonLeafHash)
	assert.Nil(t, err)

	assert.Equal(t, 3+2+2+1, nonLeafHashCount)
  assert.Equal(t, 4, leafHashCount)

  expectedRoot := []byte{70, 192, 54, 135, 85, 97, 23, 149, 170, 117, 239, 21, 118, 153, 76, 134}
  assert.Equal(t, bytes.Equal(tree.GetRoot(), expectedRoot), true)
}

func TestCacheWithoutEmptyLeaves(t *testing.T) {

	items := [][]byte{[]byte("alpha1"), []byte("alpha2"), []byte("alpha3"),[]byte("alpha1"), []byte("alpha2"), []byte("alpha3"),[]byte("alpha4"),[]byte("alpha4"),[]byte("alpha1"), []byte("alpha2"), []byte("alpha3"),[]byte("alpha4"),[]byte("alpha1"), []byte("alpha2"), []byte("alpha3"),[]byte("alpha4")}

	leafHashCount := 0
	nonLeafHashCount := 0
	hash := md5.New()
	decoratedLeafHash := NewHashCountDecorator(hash, &leafHashCount)
	decoratedNonLeafHash := NewHashCountDecorator(hash, &nonLeafHashCount)
	tree := NewSMT()
	err := tree.GenerateByTwoHashFunc(items, decoratedLeafHash, decoratedNonLeafHash)
	assert.Nil(t, err)

	assert.Equal(t, 8 + 4 + 2 + 1, nonLeafHashCount)
	assert.Equal(t, 16, leafHashCount)
  expectedRoot := []byte{205, 164, 193, 8, 222, 239, 25, 20, 59, 98, 152, 44, 87, 29, 166, 240}
  assert.Equal(t, bytes.Equal(tree.GetRoot(), expectedRoot), true)

}


