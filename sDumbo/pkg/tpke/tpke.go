package tpke

import (
	"bytes"
	"encoding/binary"
	"errors"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/share"
)

type hashablePoint interface {
	Hash([]byte) kyber.Point
}

func Encrypt(suite pairing.Suite, encPK kyber.Point, msg []byte) ([]byte, error) {
	random := suite.RandomStream()
	r := suite.G2().Scalar().Pick(random)

	U := suite.G2().Point().Mul(r, suite.G2().Point().Base()) //U=rP in G2
	G := suite.G2().Point().Mul(r, encPK)                     //G=rY in G2

	V, err := xorHash(G, msg)
	if err != nil {
		return nil, err
	}

	H, err := hashG2G1(suite, U, V)   //hash U (in G2) and V (bytes) to H (in G1)
	W := suite.G1().Point().Mul(r, H) // W=rH in G1

	return marshalCipherText(U, W, V) //ciphertext : {U,W,V}
}

func DecShare(suite pairing.Suite, sk *share.PriShare, ct []byte) ([]byte, error) {
	U, _, _, err := unmarshalCipherText(suite, ct)
	if err != nil {
		return nil, err
	}
	Ui := suite.G2().Point().Mul(sk.V, U)

	//TODO: check the validation of ct  e(P,W)=e(U,H)

	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.BigEndian, uint16(sk.I))
	if err != nil {
		return nil, err
	}
	bUi, err := Ui.MarshalBinary()
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.BigEndian, bUi)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func VerifyDecShare(suite pairing.Suite, vk []*share.PubShare, ct []byte, decShare []byte) bool {
	var index uint16
	buf := bytes.NewReader(decShare)
	err := binary.Read(buf, binary.BigEndian, &index)
	if err != nil {
		return false
	}

	Ui := suite.G2().Point()
	err = Ui.UnmarshalBinary(decShare[2:])
	if err != nil {
		return false
	}

	U, W, V, err := unmarshalCipherText(suite, ct)
	H, err := hashG2G1(suite, U, V)

	left := suite.Pair(H, Ui)
	right := suite.Pair(W, vk[index].V)

	return left.Equal(right)
}

func Decrypt(suite pairing.Suite, vk []*share.PubShare, ct []byte, decShares [][]byte, t, n int) ([]byte, error) {
	pubShares := make([]*share.PubShare, 0)
	for _, s := range decShares {
		if !VerifyDecShare(suite, vk, ct, s) {
			return nil, errors.New("valid decshare")
		}

		var i uint16
		buf := bytes.NewReader(s)
		err := binary.Read(buf, binary.BigEndian, &i)
		if err != nil {
			return nil, err
		}
		Ui := suite.G2().Point()
		err = Ui.UnmarshalBinary(s[2:])
		if err != nil {
			return nil, err
		}
		pubShares = append(pubShares, &share.PubShare{I: int(i), V: Ui})
		if len(pubShares) >= t {
			break
		}
	}
	G, err := share.RecoverCommit(suite.G2(), pubShares, t, n)
	if err != nil {
		return nil, err
	}
	//TODO: check the validation of ct  e(P,W)=e(U,H)
	_, _, V, err := unmarshalCipherText(suite, ct)
	msg, err := xorHash(G, V)

	return msg, nil

}
