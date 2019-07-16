package merkle

import (
	"crypto/md5"
	"errors"
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

type HashCountErrorDecorator struct {
	Hash             hash.Hash
	CountHappenError int
	Count            *int
}

func (decor HashCountErrorDecorator) Write(p []byte) (n int, err error) {
	*decor.Count = *decor.Count + 1
	if (*decor.Count) >= decor.CountHappenError {
		return 0, errors.New("Hash error")
	}
	return decor.Hash.Write(p)
}

func (decor HashCountErrorDecorator) Sum(b []byte) []byte {
	return decor.Hash.Sum(b)
}

func (decor HashCountErrorDecorator) BlockSize() int {
	return decor.Hash.BlockSize()
}

func (decor HashCountErrorDecorator) Size() int {
	return decor.Hash.Size()
}

func (decor HashCountErrorDecorator) Reset() {
	decor.Hash.Reset()
}

func NewHashCountErrorDecorator(h hash.Hash, count *int, countHappenError int) HashCountErrorDecorator {
	return HashCountErrorDecorator{Hash: h, Count: count, CountHappenError: countHappenError}
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

func TestInvalidArgument(t *testing.T) {
	hash := hashFunc
	tree := NewSMT(emptyHash, hash)
	err := tree.Generate(testHashes, 31)
	assert.Equal(t, err.Error(), "Leaves number of SMT tree should be power of 2")

	tree = NewSMT(emptyHash, hash)
	err = tree.Generate(testHashes, 8)
	assert.Equal(t, err.Error(), "NonEmptyLeaves is bigger than totalSize")

}

func TestSMTNotFilled(t *testing.T) {
	hash := hashFunc
	tree := NewSMT(emptyHash, hash)
	_, err := tree.RootHash()
	assert.Equal(t, err.Error(), "SMT tree is not filled")
	_, err = tree.GetMerkleProof(1)
	assert.Equal(t, err.Error(), "SMT tree is not filled")
}

func TestHashError(t *testing.T) {
	hash := md5.New()
	items := testHashes
	hashCount := 0

	for i := 1; i <= 30; i++ {
		hashCount = 0
		decoratedHash := NewHashCountErrorDecorator(hash, &hashCount, i)
		tree := NewSMT(emptyHash, decoratedHash)

		//this will cause 15 parentHash(...) call, every call cause 2 Writes(...) call, that is why loop is 30
		err := tree.Generate(items, 16)
		assert.Equal(t, err.Error(), "Hash error")
	}

	hashCount = 0
	decoratedHash := NewHashCountErrorDecorator(hash, &hashCount, 31)
	tree := NewSMT(emptyHash, decoratedHash)
	err := tree.Generate(items, 16)
	assert.Nil(t, err)

	for i := 1; i <= 6; i++ {
		hashCount = 0
		decoratedHash := NewHashCountErrorDecorator(hash, &hashCount, i)
		tree := NewSMT(nil, decoratedHash)

		//this will cause 3 parentHash(...) call, every call cause 2 Writes(...) call, that is why loop is 6
		err := tree.Generate(nil, 8)
		assert.Equal(t, err.Error(), "Hash error")
	}

	hashCount = 0
	decoratedHash = NewHashCountErrorDecorator(hash, &hashCount, 6+1)
	tree = NewSMT(nil, decoratedHash)
	err = tree.Generate(nil, 8)
	assert.Nil(t, err)
}

func TestBigFullEmptyLeavesCache(t *testing.T) {
	hashCount := 0
	hash := hashFunc
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
	rootHash, err := tree.RootHash()
	assert.Equal(t, expectedRoot, rootHash)
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
	rootHash, err := tree.RootHash()
	assert.Equal(t, expectedRoot, rootHash)
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
	rootHash, err := tree.RootHash()
	assert.Equal(t, expectedRoot, rootHash)
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
	rootHash, err := tree.RootHash()
	assert.Equal(t, expectedRoot, rootHash)
	assert.Equal(t, 16+8+4+2+1, totalHashes(tree.fullNodes))
}

func TestGetMerkleProofs(t *testing.T) {
	hash := hashFunc
	items := testHashes[:4]

	tree := NewSMT(emptyHash, hash)
	err := tree.Generate(items, 8)
	assert.Nil(t, err)

	//proof of []byte("alpha3")
	proof, err := tree.GetMerkleProof(1)

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
