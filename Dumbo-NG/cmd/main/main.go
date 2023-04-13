package main

import (
	"Dumbo-NG/internal/aab"
	"Dumbo-NG/internal/party"
	"Dumbo-NG/pkg/config"
	"Dumbo-NG/pkg/core"
	"Dumbo-NG/pkg/utils/logger"
	"crypto/rand"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/360EntSecGroup-Skylar/excelize"
)

func main() {
	log.Println("start consensus init")
	B, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Fatalln(err)
	}

	c, err := config.NewConfig("./config.yaml", true)
	if err != nil {
		log.Fatalln(err)
	}
	logg := logger.NewLoggerWithID("config", c.PID)
	tssConfig := config.TSSconfig{}
	err = tssConfig.UnMarshal(c.TSSconfig)
	if err != nil {
		logg.Fatalf("fail to unmarshal tssConfig: %s", err.Error())
	}

	p := party.NewHonestParty(uint32(c.N), uint32(c.F), uint32(c.PID), c.IPList, c.PortList, tssConfig.Pk, tssConfig.Sk)
	p.InitReceiveChannel()

	time.Sleep(time.Second * time.Duration(c.PrepareTime))

	p.InitSendChannel()

	txlength := 250
	inputChannel := make(chan []byte, 1024)
	outputChannel := make(chan []byte, 1024)
	shutdownChannel := make([]chan bool, p.N+1)
	for i := uint32(0); i <= p.N; i++ {
		shutdownChannel[i] = make(chan bool, 10)
	}

	if B == 0 {
		B = c.N
	}

	data := make([]byte, txlength*B/c.N)
	rand.Read(data)
	go func() {
		for e := 1; ; e++ {
			inputChannel <- data
		}
	}()

	st := time.Now()
	resultLen := 0
	log.Println("start consensus for B=", B)
	go aab.MainProgress(p, inputChannel, outputChannel, shutdownChannel)

	titleList := []string{"ID", "txNums", "Lantency", "Traffic", "Epochs"}
	f := excelize.NewFile()
	f.SetSheetRow("Sheet1", "A1", &titleList)

	for e := 1; e <= c.TestEpochs; e++ {
		value := <-outputChannel
		resultLen += len(value)

		txNums := resultLen / txlength
		lantency := time.Since(st).Seconds()
		core.Mu.Lock()
		traffic := core.Traffic
		core.Mu.Unlock()
		f.SetSheetRow("Sheet1", "A2", &[]interface{}{p.PID, txNums, lantency, traffic, e})
		if err := f.SaveAs("statistic.xlsx"); err != nil {
			log.Fatal(err)
		}
	}

	for i := uint32(0); i <= p.N; i++ {
		shutdownChannel[i] <- true
	}

	time.Sleep(time.Second * time.Duration(c.WaitTime))
}
