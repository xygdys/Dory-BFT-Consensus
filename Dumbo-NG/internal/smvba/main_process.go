package smvba

import (
	"Dumbo-NG/internal/party"
	"Dumbo-NG/pkg/core"
	"Dumbo-NG/pkg/protobuf"
	"Dumbo-NG/pkg/utils"
	"bytes"
	"context"
	"sync"

	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign/tbls"
)

// MainProcess is the main process of smvba instances
func MainProcess(p *party.HonestParty, ID []byte, value []byte, validation []byte, pCommit []uint32, Q func(*party.HonestParty, []byte, []byte, []byte, []uint32, *sync.Map, *sync.Map) error) ([]byte, []byte) {
	haltChannel1 := make(chan []byte, 1024) //control all round
	haltChannel2 := make(chan []byte, 1024) //control all round
	ctx, cancel := context.WithCancel(context.Background())

	hashVerifyMap := sync.Map{}
	sigVerifyMap := sync.Map{}

	for r := uint32(0); ; r++ {
		spbCtx, spbCancel := context.WithCancel(ctx) //son of ctx
		wg := sync.WaitGroup{}
		wg.Add(int(p.N + 1)) //n SPBReceiver and 1 SPBSender instances

		Lr := sync.Map{} //Lock Set
		Fr := sync.Map{} //Finish Set
		doneFlagChannel := make(chan bool, 1)
		leaderChannel := make(chan uint32, 1)    //for main progress
		preVoteFlagChannel := make(chan bool, 1) //Yes or No
		preVoteYesChannel := make(chan []byte, 3)
		preVoteNoChannel := make(chan []byte, 2)
		voteFlagChannel := make(chan byte, 1)
		voteYesChannel := make(chan []byte, 2)
		voteNoChannel := make(chan []byte, 1)
		voteOtherChannel := make(chan []byte, 1)

		//TODO: CheckValue

		//Initialize SPB instances
		var buf bytes.Buffer
		buf.Write(ID)
		buf.Write(utils.Uint32ToBytes(r))
		IDr := buf.Bytes()

		IDrj := make([][]byte, 0, p.N)
		for j := uint32(0); j < p.N; j++ {
			var buf bytes.Buffer
			buf.Write(IDr)
			buf.Write(utils.Uint32ToBytes(j))
			IDrj = append(IDrj, buf.Bytes())
		}

		for i := uint32(0); i < p.N; i++ {
			go func(j uint32) {
				var validator func(*party.HonestParty, []byte, []byte, []byte, []uint32, *sync.Map, *sync.Map) error
				if r == 0 {
					validator = Q
				} else {
					validator = nil
				}
				value, validation, sig, ok := spbReceiver(spbCtx, p, j, IDrj[j], validator, pCommit, &hashVerifyMap, &sigVerifyMap)
				if ok { //save Lock
					Lr.Store(j, &protobuf.Lock{
						Value:      value,
						Validation: validation,
						Sig:        sig,
					})
				}
				wg.Done()
			}(i)
		}

		//Run this party's SPB instance
		go func() {
			value, validation, sig, ok := spbSender(spbCtx, p, IDrj[p.PID], value, validation)
			if ok {
				finishMessage := core.Encapsulation("Finish", IDr, p.PID, &protobuf.Finish{
					Value:      value,
					Validation: validation,
					Sig:        sig,
				})
				p.Broadcast(finishMessage)
			}

			wg.Done()
		}()

		//Run Message Handlers
		go messageHandler(ctx, p, IDr, IDrj, &Fr,
			doneFlagChannel,
			preVoteFlagChannel, preVoteYesChannel, preVoteNoChannel,
			voteFlagChannel, voteYesChannel, voteNoChannel, voteOtherChannel,
			leaderChannel, haltChannel1, haltChannel2, r)

		//doneFlag -> common coin
		go election(ctx, p, IDr, doneFlagChannel)

		//leaderChannel -> shortcut -> prevote||vote||viewchange
		select {
		case result := <-haltChannel1:
			validation := <-haltChannel2
			spbCancel()
			cancel()
			return result, validation
		case l := <-leaderChannel:
			spbCancel()
			wg.Wait()

			//short-cut
			value1, ok1 := Fr.Load(l)
			if ok1 {
				finish := value1.(*protobuf.Finish)
				haltMessage := core.Encapsulation("Halt", IDr, p.PID, &protobuf.Halt{
					Value:      finish.Value,
					Validation: finish.Validation,
					Sig:        finish.Sig,
				})
				p.Broadcast(haltMessage)
				cancel()
				return finish.Value, finish.Validation
			}

			//preVote
			go preVote(ctx, p, IDr, l, &Lr)

			//vote
			go vote(ctx, p, IDr, l, preVoteFlagChannel, preVoteYesChannel, preVoteNoChannel, r)

			//result
			select {
			case result := <-haltChannel1:
				validation := <-haltChannel2
				cancel()
				return result, validation
			case flag := <-voteFlagChannel:

				if flag == 0 { //Yes
					value := <-voteYesChannel
					validation := <-voteYesChannel
					sig := <-voteYesChannel
					haltMessage := core.Encapsulation("Halt", IDr, p.PID, &protobuf.Halt{
						Value:      value,
						Validation: validation,
						Sig:        sig,
					})
					p.Broadcast(haltMessage)
					cancel()
					return value, validation
				} else if flag == 1 { //No
					sig := <-voteNoChannel
					validation = append(validation, sig...)
				} else {
					//overwrite
					value = <-voteOtherChannel
					validation = <-voteOtherChannel
				}
			}
		}
	}
}

func election(ctx context.Context, p *party.HonestParty, IDr []byte, doneFlageChannel chan bool) {
	select {
	case <-ctx.Done():
		return
	case <-doneFlageChannel:
		var buf bytes.Buffer
		buf.Write([]byte("Done"))
		buf.Write(IDr)
		coinName := buf.Bytes()

		coinShare, _ := tbls.Sign(pairing.NewSuiteBn256(), p.SigSK, coinName) //sign("Done"||ID||r||coin share)
		doneMessage := core.Encapsulation("Done", IDr, p.PID, &protobuf.Done{
			CoinShare: coinShare,
		})

		p.Broadcast(doneMessage)

	}
}

func preVote(ctx context.Context, p *party.HonestParty, IDr []byte, l uint32, Lr *sync.Map) {
	value2, ok2 := Lr.Load(l)
	if ok2 {
		lock := value2.(*protobuf.Lock)
		preVoteMessage := core.Encapsulation("PreVote", IDr, p.PID, &protobuf.PreVote{
			Vote:       true,
			Value:      lock.Value,
			Validation: lock.Validation,
			Sig:        lock.Sig,
		})
		p.Broadcast(preVoteMessage)
	} else {
		var buf bytes.Buffer
		buf.WriteByte(byte(0)) //false
		buf.Write(IDr)
		sm := buf.Bytes()
		sigShare, _ := tbls.Sign(pairing.NewSuiteBn256(), p.SigSK, sm) //sign(false||ID||r)
		preVoteMessage := core.Encapsulation("PreVote", IDr, p.PID, &protobuf.PreVote{
			Vote:       false,
			Value:      nil,
			Validation: nil,
			Sig:        sigShare,
		})
		p.Broadcast(preVoteMessage)
	}
}

func vote(ctx context.Context, p *party.HonestParty, IDr []byte, l uint32, preVoteFlagChannel chan bool, preVoteYesChannel chan []byte, preVoteNoChannel chan []byte, r uint32) {
	select {
	case <-ctx.Done():
		return
	case VoteFlag := <-preVoteFlagChannel:
		if VoteFlag { //have received a valid Yes PreVote
			value := <-preVoteYesChannel
			validation := <-preVoteYesChannel
			sig := <-preVoteYesChannel
			sigShare := <-preVoteYesChannel
			voteMessage := core.Encapsulation("Vote", IDr, p.PID, &protobuf.Vote{
				Vote:       true,
				Value:      value,
				Validation: validation,
				Sig:        sig,
				Sigshare:   sigShare,
			})
			p.Broadcast(voteMessage)
		} else { //have received 2f+1 valid No PreVote
			sig := <-preVoteNoChannel
			sigShare := <-preVoteNoChannel
			voteMessage := core.Encapsulation("Vote", IDr, p.PID, &protobuf.Vote{
				Vote:       false,
				Value:      nil,
				Validation: nil,
				Sig:        sig,
				Sigshare:   sigShare,
			})
			p.Broadcast(voteMessage)
		}
	}
}
