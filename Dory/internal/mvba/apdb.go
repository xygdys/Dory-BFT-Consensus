package mvba //smvba with dispersal-then-recast

import (
	"Dory/internal/party"
	"Dory/pkg/core"
	"Dory/pkg/protobuf"
	"Dory/pkg/reedsolomon"
	"Dory/pkg/vectorcommitment"
	"bytes"

	"github.com/vivint/infectious"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign/tbls"
)

//PDSender is run by senders of provable dispersal subprotocols
func PDSender(p *party.HonestParty, ID []byte, value []byte) ([]byte, []byte) {
	//rs encode
	rsCoder := reedsolomon.NewRScoder(int(p.F+1), int(p.N))
	shares := rsCoder.Encode(value)

	//commit
	m := make([][]byte, p.N)
	for i := uint32(0); i < p.N; i++ {
		m[i] = shares[i].Data
	}
	vCommiter, _ := vectorcommitment.NewMerkleTree(m)
	vc := vCommiter.GetMerkleTreeRoot()

	//open and send
	for i := uint32(0); i < p.N; i++ {
		proof1, proof2 := vCommiter.GetMerkleTreeProof(int(i))
		storeMessage := core.Encapsulation("Store", ID, p.PID, &protobuf.Store{
			Vc:     vc,
			Shard:  m[i],
			Proof1: proof1,
			Proof2: proof2,
		})
		p.Send(storeMessage, i)
	}

	sigs := [][]byte{}
	var buf bytes.Buffer
	buf.Write([]byte("Stored"))
	buf.Write(ID)
	buf.Write(vc)
	sm := buf.Bytes()

	for {
		m := <-p.GetMessage("Stored", ID)

		payload := core.Decapsulation("Stored", m).(*protobuf.Stored)

		sigs = append(sigs, payload.Sigshare)
		if len(sigs) > int(2*p.F) {
			signature, _ := tbls.Recover(pairing.NewSuiteBn256(), p.SigPK, sm, sigs, int(2*p.F+1), int(p.N))
			return vc, signature //lock
		}
	}
}

//PDReceiver is run by receivers of provable dispersal subprotocols
func PDReceiver(p *party.HonestParty, sender uint32, ID []byte) ([]byte, []byte, [][]byte, []int64, bool) {
	m := <-p.GetMessage("Store", ID)

	payload := (core.Decapsulation("Store", m)).(*protobuf.Store)
	ok := vectorcommitment.VerifyMerkleTreeProof(payload.Vc, payload.Proof1, payload.Proof2, payload.Shard)
	if !ok { //sender is dishonest
		return nil, nil, nil, nil, false
	}

	var buf bytes.Buffer
	buf.Write([]byte("Stored"))
	buf.Write(ID)
	buf.Write(payload.Vc)
	sm := buf.Bytes()
	sigShare, _ := tbls.Sign(pairing.NewSuiteBn256(), p.SigSK, sm) //sign("Stored"||ID||vc)

	storedMessage := core.Encapsulation("Stored", ID, p.PID, &protobuf.Stored{
		Sigshare: sigShare,
	})
	p.Send(storedMessage, sender)

	return payload.Vc, payload.Shard, payload.Proof1, payload.Proof2, true

}

//Recast is run by all parties of recast subprotocols
func Recast(p *party.HonestParty, ID []byte, leader uint32, vc []byte, shard []byte, proof1 [][]byte, proof2 []int64) ([]byte, bool) {
	if shard != nil {
		recastMessage := core.Encapsulation("Recast", ID, p.PID, &protobuf.Recast{
			Shard:  shard,
			Proof1: proof1,
			Proof2: proof2,
		})
		p.Broadcast(recastMessage)
	}

	rsCoder := reedsolomon.NewRScoder(int(p.F+1), int(p.N))
	shares := []infectious.Share{}

	for {
		m := <-p.GetMessage("Recast", ID)
		payload := (core.Decapsulation("Recast", m)).(*protobuf.Recast)
		ok := vectorcommitment.VerifyMerkleTreeProof(vc, payload.Proof1, payload.Proof2, payload.Shard)
		if ok {
			shares = append(shares, infectious.Share{
				Data:   payload.Shard,
				Number: int(m.Sender),
			})
			if len(shares) > int(2*p.F) {
				value, err := rsCoder.Decode(shares) //decode
				if err != nil {
					panic(err)
				}

				tempShares := rsCoder.Encode(value) //re-encode

				m := make([][]byte, p.N)
				for i := uint32(0); i < p.N; i++ {
					m[i] = tempShares[i].Data
				}
				tempVCommiter, _ := vectorcommitment.NewMerkleTree(m) //re-commit
				tempVC := tempVCommiter.GetMerkleTreeRoot()
				if bytes.Equal(vc, tempVC) {
					return value, true
				}
				return nil, false
			}
		}

	}
}
