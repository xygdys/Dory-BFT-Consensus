package aab

import (
	"Dumbo-NG/internal/party"
	"Dumbo-NG/internal/smvba"
	"Dumbo-NG/pkg/core"
	"Dumbo-NG/pkg/protobuf"
	"Dumbo-NG/pkg/reedsolomon"
	"Dumbo-NG/pkg/utils"
	"Dumbo-NG/pkg/vectorcommitment"
	"bytes"
	"errors"
	"log"
	"sync"

	"github.com/shirou/gopsutil/mem"
	"github.com/vivint/infectious"
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
	go Helper(p, pStore, pLock)

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
		resultValue, validation := smvba.MainProcess(p, utils.Uint32ToBytes(e), value, validation, pCommit, Q)

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
					// preTx, _ := pStore.load(s - 1)

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

func Helper(p *party.HonestParty, pStore []*store, pLock []*lock) {
	coder := reedsolomon.NewRScoder(int(p.F+1), int(p.N))
	for {
		m := <-p.GetMessage("CallHelp", []byte{})
		payload := core.Decapsulation("CallHelp", m).(*protobuf.CallHelp)

		pLock[payload.Pid].mutex.Lock()
		locked := pLock[payload.Pid].slot
		pLock[payload.Pid].mutex.Unlock()

		if locked >= payload.Slot {
			value, _ := pStore[payload.Pid].load(payload.Slot)

			temp := coder.Encode(value)
			fragments := make([][]byte, p.N)
			for i := uint32(0); i < p.N; i++ {
				fragments[i] = temp[i].Data
			}
			vCommiter, _ := vectorcommitment.NewMerkleTree(fragments)
			root := vCommiter.GetMerkleTreeRoot()
			proof1, proof2 := vCommiter.GetMerkleTreeProof(int(p.PID))

			var IDbuf bytes.Buffer
			IDbuf.Write(utils.Uint32ToBytes(payload.Pid))
			helpMessage := core.Encapsulation("Help", IDbuf.Bytes(), p.PID, &protobuf.Help{
				Pid:    payload.Pid,
				Slot:   payload.Slot,
				Shard:  fragments[p.PID],
				Root:   root,
				Proof1: proof1,
				Proof2: proof2,
			})
			p.Send(helpMessage, m.Sender)
		} else {
			value, ok1 := pStore[payload.Pid].load(payload.Slot)
			if ok1 {
				h := sha3.Sum512(value)
				var buf bytes.Buffer
				buf.Write([]byte("Proposal"))
				buf.Write(utils.Uint32ToBytes(payload.Pid))
				buf.Write(utils.Uint32ToBytes(payload.Slot))
				buf.Write(h[:])
				sm := buf.Bytes()
				err := bls.Verify(pairing.NewSuiteBn256(), p.SigPK.Commit(), sm, payload.Sig) //verify("Proposal"||e||j||h)
				if err == nil {
					pLock[payload.Pid].set(payload.Slot, h[:], payload.Sig)

					temp := coder.Encode(value)
					fragments := make([][]byte, p.N)
					for i := uint32(0); i < p.N; i++ {
						fragments[i] = temp[i].Data
					}
					vCommiter, _ := vectorcommitment.NewMerkleTree(fragments)
					root := vCommiter.GetMerkleTreeRoot()
					proof1, proof2 := vCommiter.GetMerkleTreeProof(int(p.PID))

					var IDbuf bytes.Buffer
					IDbuf.Write(utils.Uint32ToBytes(payload.Pid))
					helpMessage := core.Encapsulation("Help", IDbuf.Bytes(), p.PID, &protobuf.Help{
						Pid:    payload.Pid,
						Slot:   payload.Slot,
						Shard:  fragments[p.PID],
						Root:   root,
						Proof1: proof1,
						Proof2: proof2,
					})
					p.Send(helpMessage, m.Sender)
				}
			}
		}

	}
}

func CallHelp(p *party.HonestParty, pStore []*store, pLock []*lock, j uint32, maxSlot uint32, maxHash []byte, maxSig []byte, wg *sync.WaitGroup) { //pid, slot, hash, sig, return channel

	pLock[j].mutex.Lock()
	locked := pLock[j].slot
	pLock[j].mutex.Unlock()

	var buf bytes.Buffer
	buf.Write([]byte("Proposal"))
	buf.Write(utils.Uint32ToBytes(j))
	buf.Write(utils.Uint32ToBytes(maxSlot))
	buf.Write(maxHash)
	sm := buf.Bytes()
	err := bls.Verify(pairing.NewSuiteBn256(), p.SigPK.Commit(), sm, maxSig) //verify("Proposal"||e||j||h)

	coder := reedsolomon.NewRScoder(int(p.F+1), int(p.N))

	if maxSlot > locked && err == nil {

		shards := make([][]infectious.Share, maxSlot-locked)

		for k := locked + 1; k <= maxSlot; k++ {
			if k < maxSlot {
				callMessage := core.Encapsulation("CallHelp", []byte{}, p.PID, &protobuf.CallHelp{
					Pid:  j,
					Slot: k,
				})
				p.Broadcast(callMessage)
			} else {
				callMessage := core.Encapsulation("CallHelp", []byte{}, p.PID, &protobuf.CallHelp{
					Pid:  j,
					Slot: k,
					Sig:  maxSig,
				})
				p.Broadcast(callMessage)
			}
		}

		flag := make([]bool, maxSlot-locked)
		count := 0

		for {
			var IDbuf bytes.Buffer
			IDbuf.Write(utils.Uint32ToBytes(j))
			m := <-p.GetMessage("Help", IDbuf.Bytes())
			payload := core.Decapsulation("Help", m).(*protobuf.Help)
			if payload.Slot <= locked || payload.Slot > maxSlot || flag[payload.Slot-locked-1] { //drop old mesages
				continue
			}
			if vectorcommitment.VerifyMerkleTreeProof(payload.Root, payload.Proof1, payload.Proof2, payload.Shard) {
				shards[payload.Slot-locked-1] = append(shards[payload.Slot-locked-1], infectious.Share{
					Data:   payload.Shard,
					Number: int(m.Sender),
				})
			}
			if len(shards[payload.Slot-locked-1]) == int(p.F+1) {
				value, err := coder.Decode(shards[payload.Slot-locked-1]) //decode
				if err != nil {
					panic(err)
				}
				pStore[j].store(payload.Slot, value)
				flag[payload.Slot-locked-1] = true
				count++
				if count == int(maxSlot-locked) {
					break
				}
			}
		}
		pLock[j].set(maxSlot, maxHash, maxSig)

	}
	wg.Done()
}

func obtainProposals(p *party.HonestParty, e uint32, pStore []*store, pLock []*lock, pCommit []uint32, certSlot []uint32, certHash [][]byte, certSig [][]byte, syncChannel []chan uint32) []byte {

	var wg sync.WaitGroup

	for i := uint32(0); i < p.N; i++ {
		pLock[i].mutex.Lock()
		if pLock[i].slot < certSlot[i] { //CallHelp
			wg.Add(1)
			go CallHelp(p, pStore, pLock, i, certSlot[i], certHash[i], certSig[i], &wg)
		}
		pLock[i].mutex.Unlock()
	}

	wg.Wait()

	output := []byte{}

	for i := uint32(0); i < p.N; i++ {
		for k := pCommit[i] + 1; k <= certSlot[i]; k++ {
			value, _ := pStore[i].load(k)
			output = append(output, value...)
		}

		pLock[i].set(certSlot[i], certHash[i], certSig[i])

		pCommit[i] = certSlot[i]

		syncChannel[i] <- certSlot[i]
	}
	return output
}

func Q(p *party.HonestParty, ID []byte, value []byte, validation []byte, pCommit []uint32, hashVerifyMap *sync.Map, sigVerifyMap *sync.Map) error {
	var L protobuf.BLockSetValue //L={(j,s,h)}
	proto.Unmarshal(value, &L)

	var S protobuf.BLockSetValidation
	proto.Unmarshal(validation, &S)

	if len(L.Hash) != int(p.N) || len(L.Pid) != int(p.N) || len(L.Slot) != int(p.N) || len(S.Sig) != int(p.N) {
		return errors.New("Q check failed1")
	}

	count := uint32(0)
	for i := uint32(0); i < p.N; i++ {
		if L.Slot[i] == 0 {
			continue
		}
		if L.Slot[i] < pCommit[L.Pid[i]] {
			return errors.New("Q check failed2")
		}

		h, ok1 := hashVerifyMap.Load(L.Pid[i])
		s, ok2 := sigVerifyMap.Load(L.Pid[i])
		if ok1 && ok2 {
			if bytes.Equal(L.Hash[i], h.([]byte)) && bytes.Equal(S.Sig[i], s.([]byte)) {
				if L.Slot[i] > pCommit[L.Pid[i]] {
					count++
				}
				continue
			} else {
				return nil
			}
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

		hashVerifyMap.Store(L.Pid[i], L.Hash[i])
		sigVerifyMap.Store(L.Pid[i], S.Sig[i])
	}

	if count > 2*p.F {
		return nil
	}

	return errors.New("Q check failed3")
}
