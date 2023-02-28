package core

import (
	"Dory-NG/pkg/protobuf"
	"Dory-NG/pkg/utils"
	"log"
	"net"

	"google.golang.org/protobuf/proto"
)

// MAXMESSAGE is the size of channels
var MAXMESSAGE = 1024

// MakeSendChannel returns a channel to send messages to hostIP
func MakeSendChannel(hostIP string, hostPort string) chan *protobuf.Message {
	var addr *net.TCPAddr
	var conn *net.TCPConn
	var err1, err2 error
	//Retry to connet to node
	retry := true
	for retry {
		addr, err1 = net.ResolveTCPAddr("tcp4", hostIP+":"+hostPort)
		conn, err2 = net.DialTCP("tcp4", nil, addr)
		if err1 != nil || err2 != nil {
			log.Fatalln("try to connect failed and retry", err1, err2)
			retry = true
			continue
		} else {
			retry = false
		}
		conn.SetKeepAlive(true)
	}
	//Make the send channel and the handle func
	sendChannel := make(chan *protobuf.Message, MAXMESSAGE*100)
	go func(conn *net.TCPConn, channel chan *protobuf.Message) {
		for {
			//Pop protobuf.Message form sendchannel
			m := <-(channel)

			//Do Marshal
			byt, err1 := proto.Marshal(m)
			if err1 != nil {
				log.Fatalln("do marshal failed", err1)
			}
			//Send bytes
			length := len(byt)
			_, err2 := conn.Write(utils.IntToBytes(length))
			_, err3 := conn.Write(byt)
			if err2 != nil || err3 != nil {
				log.Fatalln("The send channel has bread down!", err2, err3)
			}
		}
	}(conn, sendChannel)

	return sendChannel
}
