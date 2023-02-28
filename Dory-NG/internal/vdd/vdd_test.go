package vdd

import (
	"Dory-NG/internal/party"
	"bytes"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"
)

func TestCallHelp(t *testing.T) {
	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1",
		"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1",
		"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1",
		"127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883", "8884", "8885", "8886", "8887", "8888", "8889",
		"8870", "8871", "8872", "8873", "8874", "8875", "8876", "8877", "8878", "8879",
		"8860", "8861", "8862", "8863", "8864", "8865", "8866", "8867", "8868", "8869", "8859"}

	N := uint32(31)
	F := uint32(10)
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

	commonVector := [][]byte{}
	for i := uint32(0); i < N; i++ {
		data := make([]byte, 1)
		data[0] = byte(i + 2)
		rand.Read(data)
		commonVector = append(commonVector, data)
	}

	var buf bytes.Buffer
	for j := uint32(0); j < N; j++ {
		buf.Write(commonVector[j])
	}
	fmt.Println("common vector:", buf.Bytes())

	result := [][]byte{}
	var wg sync.WaitGroup
	var mu sync.Mutex
	wg.Add(int(N))

	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			inputVector := make([][]byte, N)

			for l := uint32(0); l < F+1; l++ {
				inputVector[(i+l)%N] = commonVector[(i+l)%N]
			}
			for l := uint32(F + 1); l < N; l++ {
				inputVector[(i+l)%N] = nil
			}

			output := CallHelp(p[i], []byte{0}, inputVector)
			var buf bytes.Buffer
			for j := uint32(0); j < N; j++ {
				buf.Write(output[j])
			}
			mu.Lock()
			result = append(result, buf.Bytes())
			mu.Unlock()

			wg.Done()
		}(i)
	}

	wg.Wait()
	fmt.Println("party", 0, "'s output:", result[0])
	for i := uint32(1); i < N; i++ {
		if !bytes.Equal(result[i], result[i-1]) {
			t.Error()
		}
		fmt.Println("party", i, "'s output:", result[i])
	}

}
