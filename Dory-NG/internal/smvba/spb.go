package smvba

import (
	"Dory-NG/internal/party"
	"Dory-NG/internal/smvba/pb"
	"bytes"
	"context"

	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign/bls"
	"golang.org/x/crypto/sha3"
)

// strong provable broadcast
func spbSender(ctx context.Context, p *party.HonestParty, ID []byte, value []byte, validation []byte) ([]byte, []byte, bool) {
	var buf1, buf2 bytes.Buffer
	buf1.Write(ID)
	buf1.WriteByte(1)
	buf2.Write(ID)
	buf2.WriteByte(2)
	ID1 := buf1.Bytes()
	ID2 := buf2.Bytes()

	_, sig1, ok1 := pb.Sender(ctx, p, ID1, value, validation)
	if ok1 {
		_, sig2, ok2 := pb.Sender(ctx, p, ID2, value, sig1)
		if ok2 {
			return value, sig2, true //FINISH
		}
	}

	return nil, nil, false

}

func spbReceiver(ctx context.Context, p *party.HonestParty, sender uint32, ID []byte, validator1 func(*party.HonestParty, []byte, []byte, []byte) error) ([]byte, []byte, bool) {
	var buf1, buf2 bytes.Buffer
	buf1.Write(ID)
	buf1.WriteByte(1)
	buf2.Write(ID)
	buf2.WriteByte(2)
	ID1 := buf1.Bytes()
	ID2 := buf2.Bytes()

	_, _, ok1 := pb.Receiver(ctx, p, sender, ID1, validator1)

	if !ok1 {
		return nil, nil, false
	}
	value, sig, ok2 := pb.Receiver(ctx, p, sender, ID2, validator2)
	if !ok2 {
		return nil, nil, false
	}

	return value, sig, true //LOCK
}

func validator2(p *party.HonestParty, ID []byte, value []byte, validation []byte) error {
	h := sha3.Sum512(value)
	var buf bytes.Buffer
	buf.Write([]byte("Echo"))
	buf.Write(ID[:len(ID)-1])
	buf.WriteByte(1)
	buf.Write(h[:])
	sm := buf.Bytes()
	err := bls.Verify(pairing.NewSuiteBn256(), p.SigPK.Commit(), sm, validation)
	return err
}
