package party

import (
	"Dumbo-NG/pkg/core"
	"Dumbo-NG/pkg/protobuf"
	"errors"
	"sync"

	"go.dedis.ch/kyber/v3/share"
)

// Party is a interface of consensus parties
type Party interface {
	send(m *protobuf.Message, des uint32) error
	broadcast(m *protobuf.Message) error
	getMessageWithType(messageType string) (*protobuf.Message, error)
}

// HonestParty is a struct of honest consensus parties
type HonestParty struct {
	N                 uint32
	F                 uint32
	PID               uint32
	ipList            []string
	portList          []string
	sendChannels      []chan *protobuf.Message
	dispatcheChannels *sync.Map

	SigPK *share.PubPoly  //tss pk
	SigSK *share.PriShare //tss sk
}

// NewHonestParty return a new honest party object
func NewHonestParty(N uint32, F uint32, pid uint32, ipList []string, portList []string, sigPK *share.PubPoly, sigSK *share.PriShare) *HonestParty {
	p := HonestParty{
		N:            N,
		F:            F,
		PID:          pid,
		ipList:       ipList,
		portList:     portList,
		sendChannels: make([]chan *protobuf.Message, N),

		SigPK: sigPK,
		SigSK: sigSK,
	}
	return &p
}

// InitReceiveChannel setup the listener and Init the receiveChannel
func (p *HonestParty) InitReceiveChannel() error {
	p.dispatcheChannels = core.MakeDispatcheChannels(core.MakeReceiveChannel(p.portList[p.PID]), p.N)
	return nil
}

// InitSendChannel setup the sender and Init the sendChannel, please run this after initializing all party's receiveChannel
func (p *HonestParty) InitSendChannel() error {
	for i := uint32(0); i < p.N; i++ {
		p.sendChannels[i] = core.MakeSendChannel(p.ipList[i], p.portList[i])
	}
	// fmt.Println(p.sendChannels, "====")
	return nil
}

// Send a message to party des
func (p *HonestParty) Send(m *protobuf.Message, des uint32) error {
	if !p.checkInit() {
		return errors.New("This party hasn't been initialized")
	}
	if des < p.N {
		p.sendChannels[des] <- m
		return nil
	}
	return errors.New("Destination id is too large")
}

// Broadcast a message to all parties
func (p *HonestParty) Broadcast(m *protobuf.Message) error {
	if !p.checkInit() {
		return errors.New("This party hasn't been initialized")
	}
	for i := uint32(0); i < p.N; i++ {
		err := p.Send(m, i)
		if err != nil {
			return err
		}
	}
	return nil
}

// GetMessage Try to get a message according to messageType, ID
func (p *HonestParty) GetMessage(messageType string, ID []byte) chan *protobuf.Message {
	value1, _ := p.dispatcheChannels.LoadOrStore(messageType, new(sync.Map))

	channelLen := p.N
	if messageType == "CallHelp" || messageType == "Help" {
		channelLen = 1024
	}
	value2, _ := value1.(*sync.Map).LoadOrStore(string(ID), make(chan *protobuf.Message, channelLen))

	return value2.(chan *protobuf.Message)
}

func (p *HonestParty) checkInit() bool {
	if p.sendChannels == nil {
		return false
	}
	return true
}
