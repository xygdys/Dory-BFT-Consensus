package aab

import (
	"Dory/internal/mvba"
	"Dory/internal/party"
	"Dory/internal/pb"
	"Dory/internal/vdd"
	"Dory/pkg/core"
	"Dory/pkg/protobuf"
	"Dory/pkg/utils"
	"bytes"
	"context"
	"errors"
	"log"
	"sort"
	"sync"

	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/sign/tbls"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
)

//MAXMESSAGE is the size of channels
var MAXMESSAGE = 1024

func MainProgress(p *party.HonestParty, inputChannel chan []byte, outputChannel chan []byte) {

	//lock->finish->commit
	var lock = state{
		b:     [][]bool{},
		mutex: new(sync.Mutex)}
	var finish = state{
		b:     [][]bool{},
		mutex: new(sync.Mutex)}

	var commit = [][]bool{} //commit dosn't need mutex as it's read and modified totally in the main gorutine

	//store proposals
	var pStore = store{
		b:     [][]bool{},
		data:  [][][]byte{},
		mutex: new(sync.Mutex)}

	//V is the common view of parties
	var V = make([]uint32, p.N)

	//view is this party's view
	var view = make([]uint32, p.N)

	proposerInvokeChannel := make(chan uint32, MAXMESSAGE)
	go proposer(p, &finish, view, proposerInvokeChannel, inputChannel)

	for e := uint32(1); ; e++ {
		lock.grow(p.N)
		finish.grow(p.N)
		commit = append(commit, make([]bool, p.N))
		pStore.grow(p.N)

		//to propose
		proposerInvokeChannel <- e

		//listen to PB instances
		lockChannelMutex := sync.Mutex{}
		lockPIDChannel := make(chan uint32, p.N)
		lockHashChannel := make(chan []byte, p.N)
		lockSigChannel := make(chan []byte, p.N)
		go listener(p, e, &lock, &finish, &pStore, lockPIDChannel, lockHashChannel, lockSigChannel, &lockChannelMutex)

		//wait to invoke MVBA
		pids := []uint32{}
		hashes := [][]byte{}
		sigs := [][]byte{}
		for i := uint32(0); i < 2*p.F+1; i++ {
			pids = append(pids, <-lockPIDChannel)
			hashes = append(hashes, <-lockHashChannel)
			sigs = append(sigs, <-lockSigChannel)
		}
		value, err1 := proto.Marshal(&protobuf.BLockSetValue{
			Pid:  pids,
			Hash: hashes,
		})
		validation, err2 := proto.Marshal(&protobuf.BLockSetValidation{
			Sig: sigs,
		})
		if err1 != nil || err2 != nil {
			log.Fatalln(err1, err2)
		}

		//wait for MVBA's output
		resultValue := mvba.MainProcess(p, utils.Uint32ToBytes(e), value, validation, Q)

		var S protobuf.BLockSetValue //S={(j,h)}
		proto.Unmarshal(resultValue, &S)

		T1 := make([]index, 2*p.F+1)
		for i := uint32(0); i < 2*p.F+1; i++ {
			ok := pStore.isStored(e, S.Pid[i])
			if ok {
				lock.set(e, S.Pid[i])
			}
			T1[i].epoch = e
			T1[i].pid = S.Pid[i]
		}
		M1 := obtainProposals(p, e, 1, &lock, &finish, commit, &pStore, T1)

		outputP1, T2 := decompose(p, e, commit, V, M1)

		M2 := obtainProposals(p, e, 2, &lock, &finish, commit, &pStore, T2)
		outputP2 := extract(M2)

		var buf bytes.Buffer
		buf.Write(outputP1)
		buf.Write(outputP2)

		outputChannel <- buf.Bytes()
	}

}

func proposer(p *party.HonestParty, finish *state, view []uint32, invokeChannel chan uint32, inputChannel chan []byte) {

	for {
		e := <-invokeChannel
		tx := <-inputChannel
		updateView(p, e, finish, view)

		proposal, _ := proto.Marshal(&protobuf.Proposal{
			Tx:   tx,
			View: view,
		})

		//Run this party's PB instance
		var buf bytes.Buffer
		buf.Write(utils.Uint32ToBytes(e))
		buf.Write(utils.Uint32ToBytes(p.PID))
		ei := buf.Bytes()
		go func() {
			h, sig, ok := pb.Sender(context.Background(), p, ei, proposal, nil)
			if ok {
				//broadcast lock message
				lockMessage := core.Encapsulation("BLock", ei, p.PID, &protobuf.BLock{
					Hash: h,
					Sig:  sig,
				})
				p.Broadcast(lockMessage)

				sigs := [][]byte{}
				var buf3 bytes.Buffer
				buf3.Write([]byte("BLocked"))
				buf3.Write(ei)
				sm := buf3.Bytes()
			done:
				for {
					m := <-p.GetMessage("BLocked", ei)
					payload := core.Decapsulation("BLocked", m).(*protobuf.BLocked)

					sigs = append(sigs, payload.Sigshare)
					if len(sigs) == int(2*p.F+1) {
						sig, _ := tbls.Recover(pairing.NewSuiteBn256(), p.SigPK, sm, sigs, int(2*p.F+1), int(p.N))
						//broadcast finish message
						finishMessage := core.Encapsulation("BFinish", ei, p.PID, &protobuf.BFinish{
							Sig: sig,
						})
						p.Broadcast(finishMessage)
						break done
					}
				}
			}
		}()
	}
}

func listener(p *party.HonestParty, e uint32, lock *state, finish *state, pStore *store, lockPIDChannel chan uint32, lockHashChannel chan []byte, lockSigChannel chan []byte, lockChannelMutex *sync.Mutex) {
	E := utils.Uint32ToBytes(e)
	for i := uint32(0); i < p.N; i++ {
		var buf bytes.Buffer
		buf.Write(E)
		buf.Write(utils.Uint32ToBytes(i))
		ej := buf.Bytes()

		//handle lock
		go func(j uint32) {
			//receive proposal
			proposal, _, _ := pb.Receiver(context.Background(), p, j, ej, nil)
			pStore.store(e, j, proposal)

			//receive lock proof
			m := <-p.GetMessage("BLock", ej)
			payload := core.Decapsulation("BLock", m).(*protobuf.BLock)
			var buf bytes.Buffer
			buf.Write([]byte("Echo"))
			buf.Write(ej)
			buf.Write(payload.Hash)
			sm := buf.Bytes()
			err := bls.Verify(pairing.NewSuiteBn256(), p.SigPK.Commit(), sm, payload.Sig) //verify("Echo"||e||j||h)
			h := sha3.Sum512(proposal)
			if err == nil && bytes.Equal(payload.Hash, h[:]) {
				//locked
				lock.set(e, j)

				var buf bytes.Buffer
				buf.Write([]byte("BLocked"))
				buf.Write(ej)
				sm := buf.Bytes()
				sigShare, _ := tbls.Sign(pairing.NewSuiteBn256(), p.SigSK, sm) //sign("BLocked"||e||j)
				lockedMessage := core.Encapsulation("BLocked", ej, p.PID, &protobuf.BLocked{
					Sigshare: sigShare,
				})
				p.Send(lockedMessage, j)

				lockChannelMutex.Lock()
				lockPIDChannel <- j
				lockHashChannel <- payload.Hash
				lockSigChannel <- payload.Sig
				lockChannelMutex.Unlock()
			}

		}(i)
		//handle finish
		go func(j uint32) {
			m := <-p.GetMessage("BFinish", ej)
			payload := core.Decapsulation("BFinish", m).(*protobuf.BFinish)
			var buf bytes.Buffer
			buf.Write([]byte("BLocked"))
			buf.Write(ej)
			sm := buf.Bytes()
			err := bls.Verify(pairing.NewSuiteBn256(), p.SigPK.Commit(), sm, payload.Sig) //verify("BLocked"||ID||j||h)
			if err == nil {
				//finished
				finish.set(e, j)
			}
		}(i)
	}
}

func updateView(p *party.HonestParty, e uint32, finish *state, view []uint32) {
	finish.mutex.Lock()
	for i := uint32(0); i < p.N; i++ {
		for j := view[i] + 1; j < e; j++ {
			if !finish.b[j-1][i] {
				view[i] = j - 1
				break
			} else if j == e-1 {
				view[i] = j
			}
		}
	}
	finish.mutex.Unlock()
}

func obtainProposals(p *party.HonestParty, e uint32, id byte, lock *state, finish *state, commit [][]bool, pStore *store, T []index) [][]byte {
	M := make([][]byte, len(T))

	lock.mutex.Lock()
	finish.mutex.Lock()
	for i, t := range T {
		if lock.b[t.epoch-1][t.pid] {
			m, _ := pStore.load(t.epoch, t.pid)
			M[i] = m
		}
		lock.b[t.epoch-1][t.pid] = true
		finish.b[t.epoch-1][t.pid] = true
		commit[t.epoch-1][t.pid] = true
	}
	lock.mutex.Unlock()
	finish.mutex.Unlock()

	var buf bytes.Buffer
	buf.Write(utils.Uint32ToBytes(e))
	buf.WriteByte(id)
	return vdd.CallHelp(p, buf.Bytes(), M)
}

func decompose(p *party.HonestParty, e uint32, commit [][]bool, V []uint32, M [][]byte) ([]byte, []index) {
	tx := []byte{}
	proposals := make([]protobuf.Proposal, len(M))
	for i, m := range M {
		proposals[i] = protobuf.Proposal{}
		proto.Unmarshal(m, &proposals[i])
		tx = append(tx, proposals[i].Tx...)
	}

	T := []index{}
	for i := uint32(0); i < p.N; i++ {
		viewsFori := make([]int, len(proposals))
		for j := 0; j < len(proposals); j++ {
			viewsFori[j] = int(proposals[j].View[i])
		}
		sort.Ints(viewsFori)
		newVi := uint32(viewsFori[len(viewsFori)-(int(p.F)+1)])
		for e := V[i] + 1; e <= newVi; e++ {
			if commit[e-1][i] == false {
				T = append(T, index{
					epoch: e,
					pid:   i,
				})
			}
		}
		V[i] = newVi
	}
	return tx, T
}

func extract(M [][]byte) []byte {
	tx := []byte{}
	proposals := make([]protobuf.Proposal, len(M))
	for i, m := range M {
		proposals[i] = protobuf.Proposal{}
		proto.Unmarshal(m, &proposals[i])
		tx = append(tx, proposals[i].Tx...)
	}
	return tx
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
