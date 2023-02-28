package smvba

import (
	"Dumbo-NG/internal/party"
	"Dumbo-NG/internal/smvba/pb"
	"bytes"
	"context"
	"sync"

	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign/bls"
	"golang.org/x/crypto/sha3"
)

// strong provable broadcast
func spbSender(ctx context.Context, p *party.HonestParty, ID []byte, value []byte, validation []byte) ([]byte, []byte, []byte, bool) {
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
			return value, validation, sig2, true //FINISH
		}
	}

	return nil, nil, nil, false

}

func spbReceiver(ctx context.Context, p *party.HonestParty, sender uint32, ID []byte, validator1 func(*party.HonestParty, []byte, []byte, []byte, []uint32, *sync.Map, *sync.Map) error, pCommit []uint32, hashVerifyMap *sync.Map, sigVerifyMap *sync.Map) ([]byte, []byte, []byte, bool) {
	var buf1, buf2 bytes.Buffer
	buf1.Write(ID)
	buf1.WriteByte(1)
	buf2.Write(ID)
	buf2.WriteByte(2)
	ID1 := buf1.Bytes()
	ID2 := buf2.Bytes()

	_, validation, ok1 := pb.Receiver(ctx, p, sender, ID1, validator1, pCommit, hashVerifyMap, sigVerifyMap)

	if !ok1 {
		return nil, nil, nil, false
	}
	value, sig, ok2 := pb.Receiver(ctx, p, sender, ID2, validator2, nil, hashVerifyMap, sigVerifyMap)
	if !ok2 {
		return nil, nil, nil, false
	}

	return value, validation, sig, true //LOCK
}

func validator2(p *party.HonestParty, ID []byte, value []byte, validation []byte, pCommit []uint32, hashVerifyMap, sigVerifyMap *sync.Map) error {
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
