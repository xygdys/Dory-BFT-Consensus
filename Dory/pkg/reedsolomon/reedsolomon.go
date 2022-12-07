package reedsolomon

import (
	"github.com/vivint/infectious"
)

//RScoder is a reedsolomon coder
type RScoder struct {
	fec *infectious.FEC
}

//NewRScoder returns a RScoder object
func NewRScoder(requried, total int) *RScoder {
	temp, _ := infectious.NewFEC(requried, total)
	coder := &RScoder{
		fec: temp,
	}
	return coder
}

//Encode returns shares of the encoded message
func (coder *RScoder) Encode(msg []byte) []infectious.Share {
	shares := make([]infectious.Share, coder.fec.Total())
	output := func(s infectious.Share) {
		shares[s.Number] = s.DeepCopy() // the memory in s gets reused, so we need to make a deep copy
	}

	paddingLength := coder.fec.Required() - (len(msg) % coder.fec.Required())
	paddingMessage := make([]byte, len(msg)+paddingLength)
	copy(paddingMessage, msg)
	paddingMessage[len(paddingMessage)-1] = byte(paddingLength) //p.F+1 == coder.Required() == paddingLength < 256, so byte is enough
	err := coder.fec.Encode(paddingMessage, output)
	if err != nil {
		panic(err)
	}

	return shares
}

//Decode returns the original message of the shares
func (coder *RScoder) Decode(shares []infectious.Share) ([]byte, error) {
	result, err := coder.fec.Decode(nil, shares)
	if err != nil {
		return nil, err
	}
	return result[:len(result)-int(result[len(result)-1])], nil
}
