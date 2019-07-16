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

func totalHashes(nodes [][]Hash) int {
	length := len(nodes)
	result := 0
	for i := 0; i < length; i++ {
		result += len(nodes[i])
	}
	return result
}

var testHashes = [][]byte{hashValue([]byte("alpha0"), hashFunc), hashValue([]byte("alpha1"), hashFunc), hashValue([]byte("alpha2"), hashFunc), hashValue([]byte("alpha3"), hashFunc), hashValue([]byte("alpha4"), hashFunc), hashValue([]byte("alpha5"), hashFunc), hashValue([]byte("alpha6"), hashFunc), hashValue([]byte("alpha7"), hashFunc), hashValue([]byte("alpha8"), hashFunc), hashValue([]byte("alpha9"), hashFunc), hashValue([]byte("alpha10"), hashFunc), hashValue([]byte("alpha11"), hashFunc), hashValue([]byte("alpha12"), hashFunc), hashValue([]byte("alpha13"), hashFunc), hashValue([]byte("alpha14"), hashFunc), hashValue([]byte("alpha15"), hashFunc)}
var emptyHash = emptyHashFunc(hashFunc)

func TestBigFullEmptyLeavesCache(t *testing.T) {
	hashCount := 0
	hash := md5.New()
	decoratedHash := NewHashCountDecorator(hash, &hashCount)
	tree := NewSMT(emptyHash, decoratedHash)

	//2^20 empty leaves
	err := tree.Generate(nil, 1<<20)
	assert.Nil(t, err)
	assert.Equal(t, 20, hashCount)
	assert.Equal(t, 0, totalHashes(tree.fullNodes))
}

func TestCacheFullEmptyLeaves(t *testing.T) {
	hashCount := 0
	hash := md5.New()
	decoratedHash := NewHashCountDecorator(hash, &hashCount)
	tree := NewSMT(emptyHash, decoratedHash)

	// 16 empty leaves
	err := tree.Generate(nil, 16)
	assert.Nil(t, err)
	assert.Equal(t, 4, hashCount)

	expectedRoot := []byte{211, 106, 3, 253, 238, 164, 19, 12, 143, 166, 236, 114, 118, 192, 223, 97}
	assert.Equal(t, expectedRoot, tree.RootHash())
	assert.Equal(t, 0, totalHashes(tree.fullNodes))
}

var hashFunc = md5.New()

func emptyHashFunc(h hash.Hash) []byte {
	defer h.Reset()
	h.Write([]byte{})
	hash := h.Sum(nil)
	return hash
}

func TestCacheWithHalveEmptyLeaves(t *testing.T) {
	items := testHashes[:2]
	tree := NewSMT(emptyHash, hashFunc)
	err := tree.Generate(items, 4)
	assert.Nil(t, err)

	hash1 := hash2Value(testHashes[0], testHashes[1], hashFunc)
	hash2 := hash2Value(emptyHash, emptyHash, hashFunc)
	expectedRoot := hash2Value(hash1, hash2, hashFunc)

	assert.Equal(t, expectedRoot, tree.RootHash())
	assert.Equal(t, 2+1+1, totalHashes(tree.fullNodes))
}

func TestCacheWithSomeEmptyLeaves(t *testing.T) {
	hash := hashFunc
	items := testHashes[:3]
	hashCount := 0
	decoratedHash := NewHashCountDecorator(hash, &hashCount)
	tree := NewSMT(emptyHash, decoratedHash)

	//13 empty leaves
	err := tree.Generate(items, 16)
	assert.Nil(t, err)
	assert.Equal(t, 3+2+2+1, hashCount)

	hash1 := hash2Value(emptyHash, emptyHash, hash)
	hash2 := hash2Value(emptyHash, emptyHash, hash)
	fourEmptyLeafHash := hash2Value(hash1, hash2, hash)

	hash1 = hash2Value(testHashes[0], testHashes[1], hash)
	hash2 = hash2Value(testHashes[2], emptyHash, hash)
	tmp := hash2Value(hash1, hash2, hash)

	left := hash2Value(tmp, fourEmptyLeafHash, hash)
	right := hash2Value(fourEmptyLeafHash, fourEmptyLeafHash, hash)

	expectedRoot := hash2Value(left, right, hash)

	assert.Equal(t, expectedRoot, tree.RootHash())
	assert.Equal(t, 3+2+1+1+1, totalHashes(tree.fullNodes))
}

func TestCacheWithoutEmptyLeaves(t *testing.T) {
	hash := hashFunc
	items := testHashes
	hashCount := 0

	decoratedHash := NewHashCountDecorator(hash, &hashCount)
	tree := NewSMT(emptyHash, decoratedHash)

	err := tree.Generate(items, 16)
	assert.Nil(t, err)

	assert.Equal(t, 8+4+2+1, hashCount)
	expectedRoot := []byte{0xac, 0xef, 0x51, 0x94, 0xbc, 0xa5, 0x1e, 0xe8, 0x6a, 0x1a, 0x2a, 0x5, 0xfd, 0x73, 0xa2, 0x3b}
	assert.Equal(t, expectedRoot, tree.RootHash())
	assert.Equal(t, 16+8+4+2+1, totalHashes(tree.fullNodes))
}

func TestGetMerkleProofs(t *testing.T) {
	hash := hashFunc
	items := testHashes[:4]

	tree := NewSMT(emptyHash, hash)
	err := tree.Generate(items, 8)
	assert.Nil(t, err)

	//proof of []byte("alpha3")
	proof := tree.GetMerkleProof(1)

	sibleHash := testHashes[0]
	proofNode := ProofNode{Left: true, Hash: sibleHash}
	expectedProof := []ProofNode{proofNode}

	sibleHash = hash2Value(testHashes[2], testHashes[3], hash)
	proofNode = ProofNode{Left: false, Hash: sibleHash}
	expectedProof = append(expectedProof, proofNode)

	tmpHash := hashValue([]byte{}, hash)
	tmpHash = hash2Value(tmpHash, tmpHash, hash)
	sibleHash = hash2Value(tmpHash, tmpHash, hash)
	proofNode = ProofNode{Left: false, Hash: sibleHash}
	expectedProof = append(expectedProof, proofNode)

	assert.Equal(t, expectedProof, proof)
}
