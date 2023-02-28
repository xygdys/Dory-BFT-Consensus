package core

import (
	"Dumbo-NG/pkg/protobuf"
	"Dumbo-NG/pkg/utils"
	"io"
	"log"
	"net"

	"google.golang.org/protobuf/proto"
)

// MakeReceiveChannel returns a channel receiving messages
func MakeReceiveChannel(port string) chan *protobuf.Message {
	var addr *net.TCPAddr
	var lis *net.TCPListener
	var err1, err2 error
	retry := true
	//Retry to make listener
	for retry {
		addr, err1 = net.ResolveTCPAddr("tcp4", ":"+port)
		lis, err2 = net.ListenTCP("tcp4", addr)
		if err1 != nil || err2 != nil {
			log.Fatalln("make listener falied and retry", err1, err2)
			retry = true
		} else {
			retry = false
		}
	}
	//Make the receive channel and the handle func
	var conn *net.TCPConn
	var err3 error
	receiveChannel := make(chan *protobuf.Message, MAXMESSAGE*100)
	go func() {
		for {
			//The handle func run forever
			conn, err3 = lis.AcceptTCP()
			conn.SetKeepAlive(true)
			if err3 != nil {
				log.Fatalln("accept a connect request failed", err3)
			}
			//Once connect to a node, make a sub-handle func to handle this connection
			go func(conn *net.TCPConn, channel chan *protobuf.Message) {
				for {
					//Receive bytes
					lengthBuf := make([]byte, 4)
					_, err1 := io.ReadFull(conn, lengthBuf)
					length := utils.BytesToInt(lengthBuf)
					buf := make([]byte, length)
					_, err2 := io.ReadFull(conn, buf)
					if err1 != nil || err2 != nil {
						log.Fatalln("The receive channel has break down", err1, err2)
						continue
					}
					//Do Unmarshal
					var m protobuf.Message
					err3 := proto.Unmarshal(buf, &m)
					if err3 != nil {
						log.Fatalln("do unmarshal failed", err3)
					}
					//Push protobuf.Message to receivechannel
					(channel) <- &m
				}

			}(conn, receiveChannel)
		}
	}()
	return receiveChannel
}
