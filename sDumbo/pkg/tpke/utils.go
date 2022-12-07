package tpke

import (
	"errors"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"golang.org/x/crypto/sha3"
)

func xorHash(G kyber.Point, msg []byte) ([]byte, error) {
	slice, err := G.MarshalBinary()
	if err != nil {
		return nil, err
	}
	hash := sha3.New256()
	hash.Write(slice[:])
	hashedG := hash.Sum(nil)
	output := make([]byte, len(msg))
	for i := range output {
		output[i] = msg[i] ^ hashedG[i%32]
	}
	return output, nil
}

func hashG2G1(suite pairing.Suite, U kyber.Point, V []byte) (kyber.Point, error) {
	hashable, ok := suite.G1().Point().(hashablePoint)
	if !ok {
		return nil, errors.New("point needs to implement hashablePoint")
	}

	temp := []byte{}
	byt, err := U.MarshalBinary()
	if err != nil {
		return nil, err
	}
	temp = append(temp, byt...)
	temp = append(temp, V...)

	return hashable.Hash(temp), nil
}

func marshalCipherText(U kyber.Point, W kyber.Point, V []byte) ([]byte, error) {
	bU, err1 := U.MarshalBinary() //128 B
	bW, err2 := W.MarshalBinary() //64 B

	if err1 != nil || err2 != nil {
		return nil, errors.New("fail to marshal tpke ciphertext")
	}

	ct := []byte{}
	ct = append(ct, bU...)
	ct = append(ct, bW...)
	ct = append(ct, V...)

	return ct, nil
}

func unmarshalCipherText(suite pairing.Suite, ct []byte) (kyber.Point, kyber.Point, []byte, error) {
	U := suite.G2().Point()
	err := U.UnmarshalBinary(ct[:128])
	if err != nil {
		return nil, nil, nil, err
	}
	W := suite.G1().Point()
	err = W.UnmarshalBinary(ct[128 : 64+128])
	if err != nil {
		return nil, nil, nil, err
	}
	V := ct[64+128:]
	return U, W, V, nil
}
