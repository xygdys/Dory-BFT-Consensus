package mvba

import (
	"Dory/internal/party"
	"Dory/pkg/protobuf"
	"Dory/pkg/utils"
	"bytes"
	"errors"
	"sync"
	"testing"

	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/sign/tbls"
	"google.golang.org/protobuf/proto"
)

func TestMainProcess(t *testing.T) {
	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1",
		"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1",
		"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1",
		"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1",
		"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1",
		"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1",
		"127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883", "8884", "8885", "8886", "8887", "8888", "8889",
		"8870", "8871", "8872", "8873", "8874", "8875", "8876", "8877", "8878", "8879",
		"8860", "8861", "8862", "8863", "8864", "8865", "8866", "8867", "8868", "8869", "8859", "7880", "7881", "7882", "7883", "7884", "7885", "7886", "7887", "7888", "7889",
		"7870", "7871", "7872", "7873", "7874", "7875", "7876", "7877", "7878", "7879",
		"7860", "7861", "7862", "7863", "7864", "7865", "7866", "7867", "7868", "7869", "7859"}

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

	testNum := 1
	var wg sync.WaitGroup
	var mu sync.Mutex
	result := make([][][]byte, testNum)

	for k := 0; k < testNum; k++ {
		ID := utils.IntToBytes(k)
		sigshare := [][]byte{}
		var buf bytes.Buffer
		buf.Write([]byte("Echo"))
		buf.Write(ID)
		buf.Write(utils.Uint32ToBytes(0))
		h := []byte("TEST")
		buf.Write(h)
		sm := buf.Bytes()
		for i := uint32(0); i < 2*F+1; i++ {
			sigShare, _ := tbls.Sign(pairing.NewSuiteBn256(), p[i].SigSK, sm)
			sigshare = append(sigshare, sigShare)
		}
		signature, _ := tbls.Recover(pairing.NewSuiteBn256(), p[0].SigPK, sm, sigshare, int(2*F+1), int(N))
		pids := make([]uint32, 2*F+1)
		hashes := make([][]byte, 2*F+1)
		sigs := make([][]byte, 2*F+1)
		for i := uint32(0); i < 2*F+1; i++ {
			pids[i] = 0
			hashes[i] = []byte("TEST")
			sigs[i] = signature
		}
		value, _ := proto.Marshal(&protobuf.BLockSetValue{
			Pid:  pids,
			Hash: hashes,
		})
		validation, _ := proto.Marshal(&protobuf.BLockSetValidation{
			Sig: sigs,
		})

		for i := uint32(0); i < N; i++ {
			wg.Add(1)
			go func(i uint32, k int) {
				ans := MainProcess(p[i], ID, value, validation, Q)
				mu.Lock()
				result[k] = append(result[k], ans)
				mu.Unlock()
				wg.Done()

			}(i, k)

		}

	}
	wg.Wait()
	for k := 0; k < testNum; k++ {
		for i := uint32(1); i < N; i++ {
			if result[k][i][0] != result[k][i-1][0] {
				t.Error()
			}
		}
	}
}

func Q(p *party.HonestParty, ID []byte, value []byte, validation []byte) error {
	var L protobuf.BLockSetValue //L={(j,h)}
	proto.Unmarshal(value, &L)

	var S protobuf.BLockSetValidation
	proto.Unmarshal(validation, &S)

	if len(L.Hash) != 2*int(p.F)+1 || len(L.Pid) != 2*int(p.F)+1 || len(S.Sig) != 2*int(p.F)+1 {
		return errors.New("Q check failed")
	}

	for i := uint32(0); i < 2*p.F+1; i++ {
		var buf bytes.Buffer
		buf.Write([]byte("Echo"))
		buf.Write(ID[:4])
		buf.Write(utils.Uint32ToBytes(L.Pid[i]))
		buf.Write(L.Hash[i])
		sm := buf.Bytes()
		err := bls.Verify(pairing.NewSuiteBn256(), p.SigPK.Commit(), sm, S.Sig[i]) //verify("Echo"||e||j||h)
		if err != nil {
			return err
		}
	}
	return nil
}
