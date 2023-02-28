package mvba

import (
	"Dory-NG/internal/party"
	"Dory-NG/internal/smvba"
	"Dory-NG/pkg/protobuf"
	"Dory-NG/pkg/utils"
	"bytes"
	"sync"

	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign/bls"
)

// MainProcess is the main process of mvba instances
func MainProcess(p *party.HonestParty, ID []byte, value []byte, validation []byte, pCommit []uint32, Q func(*party.HonestParty, []byte, []byte, []uint32) error) ([]byte, []byte) {

	Sr := sync.Map{} //Lock Set
	pdResult := make(chan []byte, 2)

	//Initialize PD instances

	IDj := make([][]byte, 0, p.N)
	for j := uint32(0); j < p.N; j++ {
		var buf bytes.Buffer
		buf.Write(ID)
		buf.Write(utils.Uint32ToBytes(j))
		IDj = append(IDj, buf.Bytes())
	}

	for i := uint32(0); i < p.N; i++ {
		go func(j uint32) {
			vc, shard, proof1, proof2, ok := PDReceiver(p, j, IDj[j])
			if ok { //save Store
				Sr.Store(j, &protobuf.Store{
					Vc:     vc,
					Shard:  shard,
					Proof1: proof1,
					Proof2: proof2,
				})
			}
		}(i)
	}

	//Run this party's PD instance
	go func() {
		var buf bytes.Buffer
		buf.Write(value)
		buf.Write(validation)
		buf.Write(utils.IntToBytes(len(validation))) //last 4 bytes is the length of validation
		valueAndValidation := buf.Bytes()

		vc, sig := PDSender(p, IDj[p.PID], valueAndValidation)
		pdResult <- vc
		pdResult <- sig

	}()

	//waiting until pd
	vc := <-pdResult
	sig := <-pdResult

	//vc -> pid||vc
	var buf bytes.Buffer
	buf.Write(utils.Uint32ToBytes(p.PID))
	buf.Write(vc)
	idAndVC := buf.Bytes()

	for r := uint32(0); ; r++ {
		var buf bytes.Buffer
		buf.Write(ID)
		buf.Write(utils.Uint32ToBytes(r))
		IDr := buf.Bytes()

		//run underlying smvba
		leaderAndVC := smvba.MainProcess(p, IDr, idAndVC, sig, validator)
		leader := utils.BytesToUint32(leaderAndVC[:4])
		leaderVC := leaderAndVC[4:]

		//umvbaCost := time.Since(st) - pdCost
		//log.Println("epoch ", ID, " underlying mvba cost:", umvbaCost)

		//recast
		tmp, ok1 := Sr.Load(leader)
		var valueAndValidation []byte
		var ok2 bool
		if ok1 {
			//have leader's Store
			valueAndValidation, ok2 = Recast(p, IDr, leader, leaderVC, tmp.(*protobuf.Store).Shard, tmp.(*protobuf.Store).Proof1, tmp.(*protobuf.Store).Proof2)
		} else {
			//don't have leader's Store
			valueAndValidation, ok2 = Recast(p, IDr, leader, leaderVC, nil, nil, nil)
		}
		if ok2 {
			validationLen := utils.BytesToUint32(valueAndValidation[len(valueAndValidation)-4:])
			resultValue := valueAndValidation[:len(valueAndValidation)-int(validationLen)-4]
			validation := valueAndValidation[len(resultValue) : len(resultValue)+int(validationLen)]

			//recastCost := time.Since(st) - pdCost - umvbaCost
			//log.Println("epoch ", ID, " recast cost:", recastCost)
			//resultValidation := valueAndValidation[len(valueAndValidation)-int(validationLen):]
			if Q(p, resultValue, validation, pCommit) == nil {
				//QCost := time.Since(st) - pdCost - umvbaCost - recastCost
				//log.Println("epoch ", ID, " Q cost:", QCost)
				return resultValue, validation
			}

		}
		//otherwise: recast failed, goto next round
	}

}

func validator(p *party.HonestParty, ID []byte, value []byte, validation []byte) error {
	var buf bytes.Buffer

	buf.Write([]byte("Stored"))
	buf.Write(ID[:4])
	buf.Write(value)
	sm := buf.Bytes()

	err := bls.Verify(pairing.NewSuiteBn256(), p.SigPK.Commit(), sm, validation)
	return err
}
