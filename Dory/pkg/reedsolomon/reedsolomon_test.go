package reedsolomon

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestEncode(t *testing.T) {
	N := uint32(40)
	F := uint32(10)
	coder := NewRScoder(int(F+1), int(N))

	msg := make([]byte, 1000)
	rand.Read(msg)
	shares := coder.Encode(msg)

	rmsg, _ := coder.Decode(shares)
	if !bytes.Equal(msg, rmsg) {
		t.Error()
	}
}
