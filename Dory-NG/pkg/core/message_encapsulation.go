package core

import (
	"Dory-NG/pkg/protobuf"
	"log"

	"google.golang.org/protobuf/proto"
)

// Encapsulation encapsulates a message to a general type(*protobuf.Message)
func Encapsulation(messageType string, ID []byte, sender uint32, payloadMessage any) *protobuf.Message {
	var data []byte
	var err error
	switch messageType {
	case "Value":
		data, err = proto.Marshal((payloadMessage).(*protobuf.Value))
	case "Echo":
		data, err = proto.Marshal((payloadMessage).(*protobuf.Echo))
	case "Lock":
		data, err = proto.Marshal((payloadMessage).(*protobuf.Lock))
	case "Finish":
		data, err = proto.Marshal((payloadMessage).(*protobuf.Finish))
	case "Done":
		data, err = proto.Marshal((payloadMessage).(*protobuf.Done))
	case "Halt":
		data, err = proto.Marshal((payloadMessage).(*protobuf.Halt))
	case "PreVote":
		data, err = proto.Marshal((payloadMessage).(*protobuf.PreVote))
	case "Vote":
		data, err = proto.Marshal((payloadMessage).(*protobuf.Vote))
	case "Store":
		data, err = proto.Marshal((payloadMessage).(*protobuf.Store))
	case "Stored":
		data, err = proto.Marshal((payloadMessage).(*protobuf.Stored))
	case "Recast":
		data, err = proto.Marshal((payloadMessage).(*protobuf.Recast))
	case "Call":
		data, err = proto.Marshal((payloadMessage).(*protobuf.Call))
	case "Weak":
		data, err = proto.Marshal((payloadMessage).(*protobuf.Weak))
	case "Strong":
		data, err = proto.Marshal((payloadMessage).(*protobuf.Strong))
	case "Proposal":
		data, err = proto.Marshal((payloadMessage).(*protobuf.Proposal))
	case "Received":
		data, err = proto.Marshal((payloadMessage).(*protobuf.Received))

	}

	if err != nil {
		log.Fatalln(err)
	}
	return &protobuf.Message{
		Type:   messageType,
		Id:     ID,
		Sender: sender,
		Data:   data,
	}
}

// Decapsulation decapsulates a message to it's original type
func Decapsulation(messageType string, m *protobuf.Message) any {
	switch messageType {
	case "Value":
		var payloadMessage protobuf.Value
		proto.Unmarshal(m.Data, &payloadMessage)
		return &payloadMessage
	case "Echo":
		var payloadMessage protobuf.Echo
		proto.Unmarshal(m.Data, &payloadMessage)
		return &payloadMessage
	case "Lock":
		var payloadMessage protobuf.Lock
		proto.Unmarshal(m.Data, &payloadMessage)
		return &payloadMessage
	case "Finish":
		var payloadMessage protobuf.Finish
		proto.Unmarshal(m.Data, &payloadMessage)
		return &payloadMessage
	case "Done":
		var payloadMessage protobuf.Done
		proto.Unmarshal(m.Data, &payloadMessage)
		return &payloadMessage
	case "Halt":
		var payloadMessage protobuf.Halt
		proto.Unmarshal(m.Data, &payloadMessage)
		return &payloadMessage
	case "PreVote":
		var payloadMessage protobuf.PreVote
		proto.Unmarshal(m.Data, &payloadMessage)
		return &payloadMessage
	case "Vote":
		var payloadMessage protobuf.Vote
		proto.Unmarshal(m.Data, &payloadMessage)
		return &payloadMessage
	case "Store":
		var payloadMessage protobuf.Store
		proto.Unmarshal(m.Data, &payloadMessage)
		return &payloadMessage
	case "Stored":
		var payloadMessage protobuf.Stored
		proto.Unmarshal(m.Data, &payloadMessage)
		return &payloadMessage
	case "Recast":
		var payloadMessage protobuf.Recast
		proto.Unmarshal(m.Data, &payloadMessage)
		return &payloadMessage
	case "Call":
		var payloadMessage protobuf.Call
		proto.Unmarshal(m.Data, &payloadMessage)
		return &payloadMessage
	case "Weak":
		var payloadMessage protobuf.Weak
		proto.Unmarshal(m.Data, &payloadMessage)
		return &payloadMessage
	case "Strong":
		var payloadMessage protobuf.Strong
		proto.Unmarshal(m.Data, &payloadMessage)
		return &payloadMessage
	case "Proposal":
		var payloadMessage protobuf.Proposal
		proto.Unmarshal(m.Data, &payloadMessage)
		return &payloadMessage
	case "Received":
		var payloadMessage protobuf.Received
		proto.Unmarshal(m.Data, &payloadMessage)
		return &payloadMessage
	default:
		var payloadMessage protobuf.Message
		proto.Unmarshal(m.Data, &payloadMessage)
		return &payloadMessage
	}
}
