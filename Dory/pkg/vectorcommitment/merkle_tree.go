package vectorcommitment

import (
	"bytes"

	m "github.com/cbergoon/merkletree"
	"golang.org/x/crypto/sha3"
)

// implement of m.Content
type implContent struct {
	x []byte
}

func buildImplContent(x []byte) *implContent {
	return &implContent{x: x}
}

func (i *implContent) CalculateHash() ([]byte, error) {
	hash := sha3.Sum512(i.x)
	return hash[:], nil
}

func (i *implContent) Equals(other m.Content) (bool, error) {
	hash1, _ := other.CalculateHash()
	hash2, _ := i.CalculateHash()
	if bytes.Equal(hash1, hash2) {
		return true, nil
	}
	return false, nil
}

//MerkleTree is a kind of vector commitment
type MerkleTree struct {
	mktree   *m.MerkleTree
	contents []m.Content
}

//NewMerkleTree generates a merkletree
func NewMerkleTree(data [][]byte) (*MerkleTree, error) {
	contents := []m.Content{}
	for _, d := range data {
		c := buildImplContent(d)
		contents = append(contents, c)
	}
	mk, err := m.NewTreeWithHashStrategy(contents, sha3.New512)
	if err != nil {
		return nil, err
	}
	return &MerkleTree{
		mktree:   mk,
		contents: contents,
	}, nil
}

//GetMerkleTreeRoot returns a merkletree root
func (t *MerkleTree) GetMerkleTreeRoot() []byte {
	return t.mktree.MerkleRoot()
}

//GetMerkleTreeProof returns a vector commitment
func (t *MerkleTree) GetMerkleTreeProof(id int) ([][]byte, []int64) {
	path, indicator, _ := t.mktree.GetMerklePath(t.contents[id])
	return path, indicator
}

//VerifyMerkleTreeProof returns a vector commitment
func VerifyMerkleTreeProof(root []byte, proof [][]byte, indicator []int64, msg []byte) bool {
	if len(proof) != len(indicator) {
		return false
	}
	itHash, _ := (&implContent{x: msg}).CalculateHash()
	for i, p := range proof {
		s := sha3.New512()
		if indicator[i] == 1 {
			s.Write(append(itHash, p...))
		} else if indicator[i] == 0 {
			s.Write(append(p, itHash...))
		} else {
			return false
		}
		itHash = s.Sum(nil)
	}
	return bytes.Equal(itHash, root)
}
