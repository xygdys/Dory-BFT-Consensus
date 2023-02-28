package aab

import (
	"Dumbo-NG/internal/party"
	"bytes"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestMainProgress(t *testing.T) {
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

	testEpochs := 30
	var wg sync.WaitGroup
	wg.Add(int(N))
	result := make([][]byte, N)
	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			inputChannel := make(chan []byte, MAXMESSAGE)
			outputChannel := make(chan []byte, MAXMESSAGE)

			shutdownChannel := make([]chan bool, N+1)
			for i := uint32(0); i <= N; i++ {
				shutdownChannel[i] = make(chan bool, 10)
			}

			//st := time.Now()

			go func() {
				for e := 1; ; e++ {
					time.Sleep(time.Millisecond * 500)
					data := []byte("p" + fmt.Sprint(i) + "s" + fmt.Sprint(e) + " ")
					//data[0] = byte(i) * 10
					//rand.Read(data)
					//time.Sleep(time.Millisecond * time.Duration(mathRand.Int()%1000))
					inputChannel <- data

				}
			}()

			go MainProgress(p[i], inputChannel, outputChannel, shutdownChannel)
			//cost := time.Duration(0)
			total := 0
			for e := 1; e <= testEpochs; e++ {
				value := <-outputChannel
				//c := time.Since(st)
				total += len(value)
				//log.Println("e:", e, "pid:", i, "time cost:", c-cost)
				if i == 0 {
					fmt.Println("e:", e, "pid", i, "output", string(value), "total=", total)
				}

				//cost = c

				result[i] = append(result[i], value...)
			}
			for i := uint32(0); i <= N; i++ {
				shutdownChannel[i] <- true
			}
			wg.Done()
		}(i)
	}
	wg.Wait()
	for i := uint32(1); i < N; i++ {
		if !bytes.Equal(result[i], result[i-1]) {
			t.Error()
		}
		//fmt.Println(result[i])
	}
}
