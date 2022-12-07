package vectorcommitment

import (
	"bytes"
	"fmt"
	"testing"
)

func TestNewMerkleTree(t *testing.T) {
	data := [][]byte{
		[]byte("hi"),
		[]byte("hello"),
		[]byte("fuck"),
		[]byte("who"),
	}
	tre, err := NewMerkleTree(data)
	if err != nil {
		t.Errorf("%s", err.Error())
	}
	b0, _ := tre.GetMerkleTreeProof(0)
	b1, _ := tre.GetMerkleTreeProof(1)

	if !bytes.Equal(b0[1], b1[1]) {
		t.Errorf("proof generate fail")
	}

	b2, _ := tre.GetMerkleTreeProof(2)
	b3, _ := tre.GetMerkleTreeProof(3)

	if !bytes.Equal(b2[1], b3[1]) {
		t.Errorf("proof generate fail")
	}
}

func TestVerifyMerkleTreeProof(t *testing.T) {
	data := [][]byte{
		[]byte("hi"),
		[]byte("hello"),
		[]byte("fuck"),
		[]byte("who"),
	}
	tre, err := NewMerkleTree(data)
	if err != nil {
		t.Errorf("%s", err.Error())
	}
	root := tre.GetMerkleTreeRoot()

	b0, indic0 := tre.GetMerkleTreeProof(0)
	//fmt.Println(b0)
	fmt.Println(indic0)
	if !VerifyMerkleTreeProof(root, b0, indic0, data[0]) {
		t.Errorf("verify fail")
	}
	b1, indic1 := tre.GetMerkleTreeProof(1)
	fmt.Println(indic1)
	if !VerifyMerkleTreeProof(root, b1, indic1, data[1]) {
		t.Errorf("verify fail")
	}
	b2, indic2 := tre.GetMerkleTreeProof(2)
	fmt.Println(indic2)
	if !VerifyMerkleTreeProof(root, b2, indic2, data[2]) {
		t.Errorf("verify fail")
	}
	b3, indic3 := tre.GetMerkleTreeProof(3)
	fmt.Println(indic3)
	if !VerifyMerkleTreeProof(root, b3, indic3, data[3]) {
		t.Errorf("verify fail")
	}
}
