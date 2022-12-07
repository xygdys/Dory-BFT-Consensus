package pb

import (
	"bytes"
	"context"
	"fmt"
	"sDumbo/internal/party"
	"sync"
	"testing"

	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign/bls"
	"golang.org/x/crypto/sha3"
)

func TestPb(t *testing.T) {
	ctx, _ := context.WithCancel(context.Background())

	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1",
		"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1",
		"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1",
		"127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883", "8884", "8885", "8886", "8887", "8888", "8889",
		"8870", "8871", "8872", "8873", "8874", "8875", "8876", "8877", "8878", "8879",
		"8860", "8861", "8862", "8863", "8864", "8865", "8866", "8867", "8868", "8869", "8859"}

	N := uint32(4)
	F := uint32(1)
	sk, pk := party.SigKeyGen(N, 2*F+1)
	epk, evk, esks := party.EncKeyGen(N, F+1)

	var p []*party.HonestParty = make([]*party.HonestParty, N)
	for i := uint32(0); i < N; i++ {
		p[i] = party.NewHonestParty(N, F, i, ipList, portList, pk, sk[i], epk, evk, esks[i])
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

	wg := sync.WaitGroup{}
	wg.Add(1)
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
		wg.Done()
	}()

	for i := uint32(0); i < N; i++ {
		go Receiver(ctx, p[i], 0, ID, nil, nil, nil)
	}

	wg.Wait()
}
