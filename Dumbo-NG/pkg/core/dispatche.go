package core

import (
	"Dumbo-NG/pkg/protobuf"
	"sync"

	"google.golang.org/protobuf/proto"
)

var Mu = new(sync.Mutex)
var Traffic = 0

// MakeDispatcheChannels dispatche messages from receiveChannel
// and make a double layer Map : (messageType) --> (id) --> (channel)
func MakeDispatcheChannels(receiveChannel chan *protobuf.Message, N uint32) *sync.Map {
	dispatcheChannels := new(sync.Map)

	go func() { //dispatcher
		for {
			m := <-(receiveChannel)
			value1, _ := dispatcheChannels.LoadOrStore(m.Type, new(sync.Map))

			channelLen := N
			if m.Type == "CallHelp" || m.Type == "Help" {
				channelLen = 1024
			}
			value2, _ := value1.(*sync.Map).LoadOrStore(string(m.Id), make(chan *protobuf.Message, channelLen))

			value2.(chan *protobuf.Message) <- m

			Mu.Lock()
			Traffic += proto.Size(m)
			Mu.Unlock()
		}
	}()
	return dispatcheChannels
}
