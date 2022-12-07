package tpke

import (
	"fmt"
	"sDumbo/internal/party"
	"testing"

	"go.dedis.ch/kyber/v3/pairing"
)

func TestEncrypt(t *testing.T) {
	pk, vk, sks := party.EncKeyGen(3, 2)

	msg := []byte{12, 32, 12, 33}
	ct, _ := Encrypt(pairing.NewSuiteBn256(), pk, msg)

	decShare0, _ := DecShare(pairing.NewSuiteBn256(), sks[0], ct)
	decShare1, _ := DecShare(pairing.NewSuiteBn256(), sks[1], ct)

	fmt.Println(VerifyDecShare(pairing.NewSuiteBn256(), vk, ct, decShare0))
	fmt.Println(VerifyDecShare(pairing.NewSuiteBn256(), vk, ct, decShare1))
	decShares := [][]byte{}
	decShares = append(decShares, decShare0)
	decShares = append(decShares, decShare1)
	pt, _ := Decrypt(pairing.NewSuiteBn256(), vk, ct, decShares, 2, 3)

	fmt.Println(pt)
}
