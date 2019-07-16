package merkle

import (
	"crypto/md5"
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
func totalHashes(nodes [][]Hash) int {
	length := len(nodes)
	result := 0
	for i := 0; i < length; i++ {
		result += len(nodes[i])
	}
	return result
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
	err = tree.Generate(nil, 1<<20)
	assert.Nil(t, err)

	assert.Equal(t, 20, nonLeafHashCount)
	assert.Equal(t, 1, leafHashCount)

	assert.Equal(t, 0, totalHashes(tree.nodesWithoutEmptyLeavesSubTree))
}

func TestCacheFullEmptyLeaves(t *testing.T) {
	//16 empty leaves
	//	items := [][]byte{[]byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, []byte{}}

	leafHashCount := 0
	nonLeafHashCount := 0
	hash := md5.New()
	decoratedLeafHash := NewHashCountDecorator(hash, &leafHashCount)
	decoratedNonLeafHash := NewHashCountDecorator(hash, &nonLeafHashCount)
	tree, err := NewSMTWithTwoHashFuncs(decoratedLeafHash, decoratedNonLeafHash)
	assert.Nil(t, err)
	err = tree.Generate(nil, 16)
	assert.Nil(t, err)
	//four levels
	assert.Equal(t, 4, nonLeafHashCount)

	assert.Equal(t, 1, leafHashCount)

	expectedRoot := []byte{211, 106, 3, 253, 238, 164, 19, 12, 143, 166, 236, 114, 118, 192, 223, 97}
	assert.Equal(t, expectedRoot, tree.RootHash())

	assert.Equal(t, 0, totalHashes(tree.nodesWithoutEmptyLeavesSubTree))
	//assert.Equal(t, 4, len(tree.Nodes))
}

func TestCacheWithHalveEmptyLeaves(t *testing.T) {
	items := [][]byte{[]byte("alpha1"), []byte("alpha2")}

	hash := md5.New()
	tree, err := NewSMTWithTwoHashFuncs(hash, hash)
	assert.Nil(t, err)
	err = tree.Generate(items, 4)
	assert.Nil(t, err)

	hash1 := hash2Value(hashValue([]byte("alpha1"), hash), hashValue([]byte("alpha2"), hash), hash)

	hash2 := hash2Value(hashValue([]byte{}, hash), hashValue([]byte{}, hash), hash)
	expectedRoot := hash2Value(hash1, hash2, hash)

	assert.Equal(t, expectedRoot, tree.RootHash())
	assert.Equal(t, 2+1+1, totalHashes(tree.nodesWithoutEmptyLeavesSubTree))
}

func TestCacheWithSomeEmptyLeaves(t *testing.T) {
	//13 empty leaves
	items := [][]byte{[]byte("alpha1"), []byte("alpha2"), []byte("alpha3")}

	leafHashCount := 0
	nonLeafHashCount := 0
	hash := md5.New()
	decoratedLeafHash := NewHashCountDecorator(hash, &leafHashCount)
	decoratedNonLeafHash := NewHashCountDecorator(hash, &nonLeafHashCount)
	tree, err := NewSMTWithTwoHashFuncs(decoratedLeafHash, decoratedNonLeafHash)
	assert.Nil(t, err)
	err = tree.Generate(items, 16)
	assert.Nil(t, err)

	assert.Equal(t, 3+2+2+1, nonLeafHashCount)
	assert.Equal(t, 4, leafHashCount)

	hash1 := hash2Value(hashValue([]byte{}, hash), hashValue([]byte{}, hash), hash)
	hash2 := hash2Value(hashValue([]byte{}, hash), hashValue([]byte{}, hash), hash)
	fourEmptyLeafHash := hash2Value(hash1, hash2, hash)

	hash1 = hash2Value(hashValue([]byte("alpha1"), hash), hashValue([]byte("alpha2"), hash), hash)
	hash2 = hash2Value(hashValue([]byte("alpha3"), hash), hashValue([]byte{}, hash), hash)
	tmp := hash2Value(hash1, hash2, hash)
	left := hash2Value(tmp, fourEmptyLeafHash, hash)

	right := hash2Value(fourEmptyLeafHash, fourEmptyLeafHash, hash)

	expectedRoot := hash2Value(left, right, hash)

	assert.Equal(t, expectedRoot, tree.RootHash())
	assert.Equal(t, 3 + 2 + 1 + 1 + 1, totalHashes(tree.nodesWithoutEmptyLeavesSubTree))
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
	err = tree.Generate(items, 16)
	assert.Nil(t, err)

	assert.Equal(t, 8+4+2+1, nonLeafHashCount)
	assert.Equal(t, 16+1, leafHashCount)
	expectedRoot := []byte{128, 114, 175, 140, 59, 253, 14, 136, 26, 157, 15, 64, 61, 36, 68, 36}
	assert.Equal(t, expectedRoot, tree.RootHash())
	//assert.Equal(t, 15+16, len(tree.Nodes))
	assert.Equal(t, 16+8+4+2+1, totalHashes(tree.nodesWithoutEmptyLeavesSubTree))
}

func TestCacheWithoutLeafHashFunc(t *testing.T) {

	//leafHashCount := 0
	nonLeafHashCount := 0
	hash := md5.New()
	decoratedNonLeafHash := NewHashCountDecorator(hash, &nonLeafHashCount)

	emptyLeafHash, err := emptyLeafHash(hash)
	assert.Nil(t, err)

	//13 empty leaves
	items := [][]byte{[]byte("alpha1"), []byte("alpha2"), []byte("alpha3")}

	tree, err := NewSMTWithNonLeafHashAndEmptyLeafHashValue(emptyLeafHash, decoratedNonLeafHash)
	assert.Nil(t, err)
	err = tree.Generate(items, 16)
	assert.Nil(t, err)

	hash1 := hash2Value(emptyLeafHash, emptyLeafHash, hash)
	fourEmptyLeafHash := hash2Value(hash1, hash1, hash)

	hash1 = hash2Value([]byte("alpha1"), []byte("alpha2"), hash)
	hash2 := hash2Value([]byte("alpha3"), emptyLeafHash, hash)
	tmp := hash2Value(hash1, hash2, hash)

	left := hash2Value(tmp, fourEmptyLeafHash, hash)
	right := hash2Value(fourEmptyLeafHash, fourEmptyLeafHash, hash)
	expectedRoot := hash2Value(left, right, hash)

	//	assert.Equal(t, 3+2+2+1, nonLeafHashCount)
	assert.Equal(t, expectedRoot, tree.RootHash())
	assert.Equal(t, 3+2+1+1+1, totalHashes(tree.nodesWithoutEmptyLeavesSubTree))
	//	assert.Equal(t, 8+4, len(tree.Nodes))
}

func hashValue(item []byte, hash hash.Hash) []byte {
	defer hash.Reset()
	hash.Write(item)
	return hash.Sum(nil)
}

func hash2Value(item1 []byte, item2 []byte, hash hash.Hash) []byte {
	defer hash.Reset()
	hash.Write(item1)
	hash.Write(item2)
	return hash.Sum(nil)
}

func TestGetMerkleProofs(t *testing.T) {
	items := [][]byte{[]byte("alpha1"), []byte("alpha2"), []byte("alpha3"), []byte("alpha4")}

	hash := md5.New()
	tree, err := NewSMTWithTwoHashFuncs(hash, hash)
	assert.Nil(t, err)
	err = tree.Generate(items, 8)
	assert.Nil(t, err)

	//proof of []byte("alpha3")
	proof := tree.GetMerkelProof(1)

	sibleHash := hashValue([]byte("alpha1"), hash)
	proofNode := ProofNode{Left: true, Hash: sibleHash}
	expectedProof := []ProofNode{proofNode}

	sibleHash = hash2Value(hashValue([]byte("alpha3"), hash), hashValue([]byte("alpha4"), hash), hash)
	proofNode = ProofNode{Left: false, Hash: sibleHash}
	expectedProof = append(expectedProof, proofNode)

	tmpHash := hashValue([]byte{}, hash)
	tmpHash = hash2Value(tmpHash, tmpHash, hash)
	sibleHash = hash2Value(tmpHash, tmpHash, hash)
	proofNode = ProofNode{Left: false, Hash: sibleHash}
	expectedProof = append(expectedProof, proofNode)

	assert.Equal(t, expectedProof, proof)
}
