package acs

import (
	"bytes"
	"sDumbo/internal/party"
	"sDumbo/pkg/utils"
	"sync"
	"testing"
)

func TestMainProcess(t *testing.T) {
	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1",
		"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1",
		"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1",
		"127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883", "8884", "8885", "8886", "8887", "8888", "8889",
		"8870", "8871", "8872", "8873", "8874", "8875", "8876", "8877", "8878", "8879",
		"8860", "8861", "8862", "8863", "8864", "8865", "8866", "8867", "8868", "8869", "8859"}

	N := uint32(16)
	F := uint32(5)
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

	testEpochs := 10
	var wg sync.WaitGroup
	wg.Add(int(N))
	result := make([][]byte, N)
	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			for e := 1; e <= testEpochs; e++ {
				data := make([]byte, 5000)
				value := MainProcess(p[i], utils.IntToBytes(e), data)
				result[i] = append(result[i], value[0]...)
			}
			wg.Done()
		}(i)
	}
	wg.Wait()
	for i := uint32(1); i < N; i++ {
		if !bytes.Equal(result[i], result[i-1]) {
			t.Error()
		}
	}
}
