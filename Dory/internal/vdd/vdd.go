package vdd //vector data dissemination

import (
	"Dory/internal/party"
	"Dory/pkg/core"
	"Dory/pkg/protobuf"
	"Dory/pkg/reedsolomon"
	"sync"

	"github.com/vivint/infectious"
	"google.golang.org/protobuf/proto"
)

type missingElementHandler struct {
	//for weakHelp message
	star       []byte
	starWait   *sync.WaitGroup
	starShares []infectious.Share

	finishFlag      bool
	finishFlagMutex *sync.Mutex

	decodeShareChannel chan infectious.Share
}

func (m *missingElementHandler) isFinish() bool {
	m.finishFlagMutex.Lock()
	result := m.finishFlag
	m.finishFlagMutex.Unlock()
	return result
}
func (m *missingElementHandler) Finish() {
	m.finishFlagMutex.Lock()
	m.finishFlag = true
	m.finishFlagMutex.Unlock()
}

func onlineErrorCorrection(p *party.HonestParty, ID []byte, coder *reedsolomon.RScoder, handlers []*missingElementHandler, outputVector [][]byte, finishWait *sync.WaitGroup) {
	for i, handler := range handlers {
		if handler == nil {
			continue
		}
		go func(i int, h *missingElementHandler) {
			decodeShares := []infectious.Share{}
			for {
				decodeShares = append(decodeShares, <-h.decodeShareChannel)
				if len(decodeShares) > int(2*p.F) {
					result, err := coder.Decode(decodeShares)
					if err != nil {
						panic(err)
					} else {
						outputVector[i] = result
						break
					}
				}
			}
			h.starWait.Wait()
			finishWait.Done()
		}(i, handler)
	}
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

//CallHelp call for help to other parties
func CallHelp(p *party.HonestParty, ID []byte, inputVector [][]byte) [][]byte {
	outputVector := make([][]byte, len(inputVector))
	coder := reedsolomon.NewRScoder(int(p.F+1), int(p.N))

	S := []uint32{}
	handlers := make([]*missingElementHandler, len(inputVector))
	for i := 0; i < len(inputVector); i++ {
		if inputVector[i] == nil {
			//missing elements
			handler := missingElementHandler{
				star:               []byte{},
				starWait:           new(sync.WaitGroup),
				starShares:         []infectious.Share{},
				finishFlag:         false,
				finishFlagMutex:    new(sync.Mutex),
				decodeShareChannel: make(chan infectious.Share, p.N),
			}
			handler.starWait.Add(1)
			handlers[i] = &handler
			S = append(S, uint32(i))
		} else {
			outputVector[i] = inputVector[i]
		}
	}

	go helpListener(p, ID, coder, inputVector, handlers)

	finishWait := sync.WaitGroup{}
	finishWait.Add(len(S))
	go onlineErrorCorrection(p, ID, coder, handlers, outputVector, &finishWait)

	haltChannel := make(chan bool, 1)
	go func() {
		finishWait.Wait()
		haltChannel <- true
	}()

	callMessage := core.Encapsulation("Call", ID, p.PID, &protobuf.Call{
		Indices: S,
	})
	for i := uint32(0); i < p.N; i++ {
		if i != p.PID {
			p.Send(callMessage, i)
		}
	}

	for {
		select {
		case <-haltChannel:
			return outputVector
		case m := <-p.GetMessage("Strong", ID):
			payload := (core.Decapsulation("Strong", m)).(*protobuf.Strong)
			for i, index := range payload.ShardIndices {
				if handlers[index] == nil { //not required
					continue
				}
				if handlers[index].isFinish() {
					continue //already finish the reconstruction of this message
				}
				tmpShare1 := infectious.Share{
					Number: int(m.Sender),
					Data:   payload.SenderShards[i],
				}
				handlers[index].decodeShareChannel <- tmpShare1

				tmpShare2 := infectious.Share{
					Number: int(p.PID),
					Data:   payload.ReceiverShards[i],
				}
				handlers[index].starShares = append(handlers[index].starShares, tmpShare2)

				if len(handlers[index].starShares) == int(p.F+1) {
					handlers[index].star = tmpShare2.Data
					handlers[index].starWait.Done()
					handlers[index].decodeShareChannel <- tmpShare2
				}
			}
		case m := <-p.GetMessage("Weak", ID):
			payload := (core.Decapsulation("Weak", m)).(*protobuf.Weak)
			for i, index := range payload.ShardIndices {
				if handlers[index] == nil { //not required
					continue
				}
				if handlers[index].isFinish() {
					continue //already finish the reconstruction of this message
				}
				tmpShare1 := infectious.Share{
					Number: int(m.Sender),
					Data:   payload.SenderShards[i],
				}
				handlers[index].decodeShareChannel <- tmpShare1
			}
		}
	}

}

func helpListener(p *party.HonestParty, ID []byte, coder *reedsolomon.RScoder, inputVector [][]byte, handlers []*missingElementHandler) {
	for i := 0; i < int(p.N); i++ { // return after replying to all parties
		m := <-p.GetMessage("Call", ID)
		payload := (core.Decapsulation("Call", m)).(*protobuf.Call)

		strongHelpIndices := []uint32{}
		strongHelpElements := [][]byte{}

		weakHelpIndices := []uint32{}

		for _, index := range payload.Indices {
			if inputVector[index] != nil {
				strongHelpIndices = append(strongHelpIndices, index)
				strongHelpElements = append(strongHelpElements, inputVector[index])
			} else {
				weakHelpIndices = append(weakHelpIndices, index)
			}
		}
		strongHelp(p, ID, coder, m.Sender, strongHelpIndices, strongHelpElements)
		go weakHelp(p, ID, m.Sender, weakHelpIndices, handlers)
	}
}

func strongHelp(p *party.HonestParty, ID []byte, coder *reedsolomon.RScoder, caller uint32, strongHelpIndices []uint32, strongHelpElements [][]byte) {
	senderShards := make([][]byte, len(strongHelpElements))
	receiverShards := make([][]byte, len(strongHelpElements))
	for i, element := range strongHelpElements {
		shares := coder.Encode(element)
		senderShards[i] = shares[p.PID].Data
		receiverShards[i] = shares[caller].Data
	}

	strongMessage := core.Encapsulation("Strong", ID, p.PID, &protobuf.Strong{
		ShardIndices:   strongHelpIndices,
		SenderShards:   senderShards,
		ReceiverShards: receiverShards,
	})

	p.Send(strongMessage, caller)
}

func weakHelp(p *party.HonestParty, ID []byte, caller uint32, weakHelpIndices []uint32, handlers []*missingElementHandler) {
	senderShards := make([][]byte, len(weakHelpIndices))
	for i, index := range weakHelpIndices {
		handlers[index].starWait.Wait()
		senderShards[i] = handlers[index].star
	}

	weakMessage := core.Encapsulation("Weak", ID, p.PID, &protobuf.Weak{
		ShardIndices: weakHelpIndices,
		SenderShards: senderShards,
	})

	p.Send(weakMessage, caller)
}
