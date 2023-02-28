package aab

import (
	"Dory-NG/internal/mvba"
	"Dory-NG/internal/party"
	"Dory-NG/internal/vdd"
	"Dory-NG/pkg/core"
	"Dory-NG/pkg/protobuf"
	"Dory-NG/pkg/utils"
	"bytes"
	"errors"
	"log"
	"sync"

	"github.com/shirou/gopsutil/mem"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/sign/tbls"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
)

// MAXMESSAGE is the size of channels
var MAXMESSAGE = 1024

func GetMemPercent() float64 {
	memInfo, _ := mem.VirtualMemory()
	return memInfo.UsedPercent
}

func MainProgress(p *party.HonestParty, inputChannel chan []byte, outputChannel chan []byte, shutdownChannel []chan bool) {

	//store proposals
	var pStore = make([]*store, p.N)
	var pLock = make([]*lock, p.N)
	for i := uint32(0); i < p.N; i++ {
		pStore[i] = &store{
			data:  [][]byte{},
			mutex: new(sync.Mutex)}
		pLock[i] = &lock{
			slot:  0,
			hash:  []byte{},
			sig:   []byte{},
			mutex: new(sync.Mutex)}
	}
	var pCommit = make([]uint32, p.N)

	syncChannel := make([]chan uint32, p.N)
	for i := uint32(0); i < p.N; i++ {
		syncChannel[i] = make(chan uint32, 1024)
	}

	// pipeline proposer
	go proposer(p, inputChannel, shutdownChannel[p.N])
	//listen to proposers
	for i := uint32(0); i < p.N; i++ {
		go listener(p, i, pStore[i], pLock[i], syncChannel[i], shutdownChannel[i])
	}

	for e := uint32(1); ; e++ {
		//wait for MVBA's output

		//wait to invoke MVBA
		pids := []uint32{}
		slots := []uint32{}
		hashes := [][]byte{}
		sigs := [][]byte{}

		flags := make([]bool, p.N)
		count := uint32(0)
		for i := uint32(0); count < 2*p.F+1; i = (i + 1) % p.N {
			if !flags[i] {
				pLock[i].mutex.Lock()
				if pLock[i].slot > pCommit[i] {
					count++
					flags[i] = true
				}
				pLock[i].mutex.Unlock()
			}
		}

		for i := uint32(0); i < p.N; i++ {
			pLock[i].mutex.Lock()
			pids = append(pids, i)
			slots = append(slots, pLock[i].slot)
			hashes = append(hashes, pLock[i].hash)
			sigs = append(sigs, pLock[i].sig)
			pLock[i].mutex.Unlock()
		}

		value, err1 := proto.Marshal(&protobuf.BLockSetValue{
			Pid:  pids,
			Slot: slots,
			Hash: hashes,
		})
		validation, err2 := proto.Marshal(&protobuf.BLockSetValidation{
			Sig: sigs,
		})
		if err1 != nil || err2 != nil {
			log.Fatalln(err1, err2)
		}
		//wait for MVBA's output
		resultValue, validation := mvba.MainProcess(p, utils.Uint32ToBytes(e), value, validation, pCommit, Q)

		var L protobuf.BLockSetValue //L={(j,s,h)}
		proto.Unmarshal(resultValue, &L)
		var S protobuf.BLockSetValidation
		proto.Unmarshal(validation, &S)

		for i := uint32(0); i < p.N; i++ {
			_, ok := pStore[L.Pid[i]].load(L.Slot[i])
			if ok { // if ok is true, then the current slot is must >= L.slot[i] and locked slot >= L.slot[i]-1
				pLock[L.Pid[i]].set(L.Slot[i], L.Hash[i], S.Sig[i])
			}

		}
		output := obtainProposals(p, e, pStore, pLock, pCommit, L.Slot, L.Hash, S.Sig, syncChannel)
		outputChannel <- output
	}

}

func proposer(p *party.HonestParty, inputChannel chan []byte, shutdownChannel chan bool) {
	var hash, signature []byte

	for s := uint32(1); ; s++ { //slot
		select {
		case <-shutdownChannel:
			return
		case tx := <-inputChannel:
			var buf1 bytes.Buffer
			buf1.Write(utils.Uint32ToBytes(p.PID))
			buf1.Write(utils.Uint32ToBytes(s))
			ID := buf1.Bytes()

			var proposalMessage *protobuf.Message
			if s == 1 {
				proposalMessage = core.Encapsulation("Proposal", ID, p.PID, &protobuf.Proposal{
					Tx: tx,
				})
			} else {
				proposalMessage = core.Encapsulation("Proposal", ID, p.PID, &protobuf.Proposal{
					Tx:   tx,
					Hash: hash,      //hash of previous slot
					Sig:  signature, // sig on previous slot
				})
			}

			p.Broadcast(proposalMessage)

			var buf2 bytes.Buffer
			sigs := [][]byte{}
			h := sha3.Sum512(tx)
			buf2.Write([]byte("Proposal"))
			buf2.Write(ID)
			buf2.Write(h[:])
			sm := buf2.Bytes()

			for {
				m := <-p.GetMessage("Received", ID)
				payload := core.Decapsulation("Received", m).(*protobuf.Received)

				sigs = append(sigs, payload.Sigshare)
				if len(sigs) > int(2*p.F) {
					hash = h[:]
					signature, _ = tbls.Recover(pairing.NewSuiteBn256(), p.SigPK, sm, sigs, int(2*p.F+1), int(p.N))
					break
				}
			}

		}

	}
}

func listener(p *party.HonestParty, j uint32, pStore *store, pLock *lock, syncChannel chan uint32, shutdownChannel chan bool) {
	var preID, ID []byte

	for s := uint32(1); ; s++ {
		preID = ID
		var buf1 bytes.Buffer
		buf1.Write(utils.Uint32ToBytes(j))
		buf1.Write(utils.Uint32ToBytes(s))
		ID = buf1.Bytes()
	slotFlag:
		for {
			select {
			case <-shutdownChannel:
				return
			case commitedSlot := <-syncChannel:
				if commitedSlot >= s {
					s = commitedSlot
					var buf2 bytes.Buffer
					buf2.Write(utils.Uint32ToBytes(j))
					buf2.Write(utils.Uint32ToBytes(s))
					ID = buf2.Bytes()
					break slotFlag
				}
			case m := <-p.GetMessage("Proposal", ID):
				payload := (core.Decapsulation("Proposal", m)).(*protobuf.Proposal)

				var buf2 bytes.Buffer
				h := sha3.Sum512(payload.Tx)
				buf2.Write([]byte("Proposal"))
				buf2.Write(ID)
				buf2.Write(h[:])
				sm := buf2.Bytes()

				if s == 1 {
					pStore.store(s, payload.Tx)
					sigShare, _ := tbls.Sign(pairing.NewSuiteBn256(), p.SigSK, sm) //sign("Proposal"||j||s||Hash(tx))
					receivedMessage := core.Encapsulation("Received", ID, p.PID, &protobuf.Received{
						Sigshare: sigShare,
					})
					p.Send(receivedMessage, j)
				} else {
					var buf3 bytes.Buffer
					buf3.Write([]byte("Proposal"))
					buf3.Write(preID)
					buf3.Write(payload.Hash)
					presm := buf3.Bytes()
					err := bls.Verify(pairing.NewSuiteBn256(), p.SigPK.Commit(), presm, payload.Sig) //verify("Proposal"||j||s-1||Hash(pre_tx))
					preTx, _ := pStore.load(s - 1)
					preHash := sha3.Sum512(preTx)
					if err == nil && bytes.Equal(payload.Hash, preHash[:]) {
						pLock.set(s-1, payload.Hash, payload.Sig)
						pStore.store(s, payload.Tx)
						sigShare, _ := tbls.Sign(pairing.NewSuiteBn256(), p.SigSK, sm) //sign("Proposal"||j||s||Hash(tx))
						receivedMessage := core.Encapsulation("Received", ID, p.PID, &protobuf.Received{
							Sigshare: sigShare,
						})
						p.Send(receivedMessage, j)
					}
				}
				break slotFlag
			}
		}

	}

}

func obtainProposals(p *party.HonestParty, e uint32, pStore []*store, pLock []*lock, pCommit []uint32, certSlot []uint32, certHash [][]byte, certSig [][]byte, syncChannel []chan uint32) []byte {

	M := [][]byte{}
	for i := uint32(0); i < p.N; i++ {
		pLock[i].mutex.Lock()
		for k := pCommit[i] + 1; k <= certSlot[i]; k++ {
			if pLock[i].slot >= k {
				m, _ := pStore[i].load(k)
				M = append(M, m)
			} else {
				M = append(M, nil)
			}
		}
		pLock[i].mutex.Unlock()
	}

	result := vdd.CallHelp(p, utils.Uint32ToBytes(e), M)

	count := 0
	for i := uint32(0); i < p.N; i++ {
		pLock[i].mutex.Lock()
		lockedFlag := pLock[i].slot
		pLock[i].mutex.Unlock()

		for k := pCommit[i] + 1; k <= certSlot[i]; k++ {
			if lockedFlag >= k {
				count++
				continue
			}
			pStore[i].store(k, result[count])
			count++
		}

		pLock[i].set(certSlot[i], certHash[i], certSig[i])

		pCommit[i] = certSlot[i]

		syncChannel[i] <- certSlot[i]
	}

	var buf bytes.Buffer
	for _, m := range result {
		buf.Write(m)
	}
	tx := buf.Bytes()
	return tx
}

func Q(p *party.HonestParty, value []byte, validation []byte, pCommit []uint32) error {
	var L protobuf.BLockSetValue //L={(j,s,h)}
	proto.Unmarshal(value, &L)

	var S protobuf.BLockSetValidation
	proto.Unmarshal(validation, &S)

	if len(L.Hash) != int(p.N) || len(L.Pid) != int(p.N) || len(L.Slot) != int(p.N) || len(S.Sig) != int(p.N) {
		return errors.New("Q check failed")
	}

	count := uint32(0)
	for i := uint32(0); i < p.N; i++ {
		if L.Slot[i] == 0 {
			continue
		}
		if L.Slot[i] < pCommit[L.Pid[i]] {
			return errors.New("Q check failed")
		}
		var buf bytes.Buffer
		buf.Write([]byte("Proposal"))
		buf.Write(utils.Uint32ToBytes(L.Pid[i]))
		buf.Write(utils.Uint32ToBytes(L.Slot[i]))
		buf.Write(L.Hash[i])
		sm := buf.Bytes()
		err := bls.Verify(pairing.NewSuiteBn256(), p.SigPK.Commit(), sm, S.Sig[i]) //verify("Proposal"||e||j||h)
		if err != nil {
			return err
		}
		if L.Slot[i] > pCommit[L.Pid[i]] {
			count++
		}
	}

	if count > 2*p.F {
		return nil
	}

	return errors.New("Q check failed")
}
