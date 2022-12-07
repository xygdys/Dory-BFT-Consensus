package pb

import (
	"Dory/internal/party"
	"bytes"
	"context"
	"fmt"
	"testing"

	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign/bls"
	"golang.org/x/crypto/sha3"
)

func TestPb(t *testing.T) {
	ctx, _ := context.WithCancel(context.Background())

	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883"}

	N := uint32(4)
	F := uint32(1)
	sk, pk := party.SigKeyGen(N, 2*F+1)

	var p []*party.HonestParty = make([]*party.HonestParty, N)
	for i := uint32(0); i < N; i++ {
		p[i] = party.NewHonestParty(N, F, i, ipList, portList, pk, sk[i])
	}

	for i := uint32(0); i < N; i++ {
		p[i].InitReceiveChannel()
	}

	for i := uint32(0); i < N; i++ {
		p[i].InitSendChannel()
	}

	value := make([]byte, 10)
	validation := make([]byte, 1)
	ID := []byte{1, 2}

	go func() {
		_, sig, _ := Sender(ctx, p[0], ID, value, validation)
		h := sha3.Sum512(value)
		var buf bytes.Buffer
		buf.Write([]byte("Echo"))
		buf.Write(ID)
		buf.Write(h[:])
		sm := buf.Bytes()

		err := bls.Verify(pairing.NewSuiteBn256(), p[0].SigPK.Commit(), sm, sig)

		fmt.Println(err)
	}()

	for i := uint32(0); i < N; i++ {
		go Receiver(ctx, p[i], 0, ID, nil)
	}

	for {

	}
}
