package aab

import (
	"log"
	"sDumbo/internal/acs"
	"sDumbo/internal/party"
	"sDumbo/pkg/core"
	"sDumbo/pkg/protobuf"
	"sDumbo/pkg/tpke"
	"sDumbo/pkg/utils"

	"github.com/shirou/gopsutil/mem"
	"go.dedis.ch/kyber/v3/pairing"
)

func GetMemPercent() float64 {
	memInfo, _ := mem.VirtualMemory()
	return memInfo.UsedPercent
}

//MAXMESSAGE is the size of channels
var MAXMESSAGE = 1024

func MainProcess(p *party.HonestParty, inputChannel chan []byte, outputChannel chan []byte) {

	for e := uint32(1); ; e++ {
		tx := <-inputChannel

		c, _ := tpke.Encrypt(pairing.NewSuiteBn256(), p.EncPK, tx)

		//invoke ACS
		ID := utils.Uint32ToBytes(e)
		cResult := acs.MainProcess(p, ID, c)

		for i, c := range cResult {
			decShare, _ := tpke.DecShare(pairing.NewSuiteBn256(), p.EncSK, c)
			decMessage := core.Encapsulation("Dec", ID, p.PID, &protobuf.Dec{
				Id:       uint32(i),
				DecShare: decShare,
			})
			p.Broadcast(decMessage)
		}

		pResult := make([][]byte, len(cResult))
		decShares := make([][][]byte, len(cResult))

		doneNum := 0
		for {
			m := <-p.GetMessage("Dec", ID)
			payload := core.Decapsulation("Dec", m).(*protobuf.Dec)
			if pResult[payload.Id] != nil {
				continue
			}
			decShares[payload.Id] = append(decShares[payload.Id], payload.DecShare)
			if len(decShares[payload.Id]) == int(p.F+1) {
				pt, err := tpke.Decrypt(pairing.NewSuiteBn256(), p.EncVK, cResult[payload.Id], decShares[payload.Id], int(p.F+1), int(p.N))
				if err != nil {
					log.Fatalln(err)
					break
				} else {
					pResult[payload.Id] = pt
					doneNum++
				}
			}

			if doneNum == len(cResult) {
				break
			}
		}

		output := []byte{}
		for _, v := range pResult {
			output = append(output, v...)
		}
		outputChannel <- output
	}
}
