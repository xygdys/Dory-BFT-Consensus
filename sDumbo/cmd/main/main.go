package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"sDumbo/internal/aab"
	"sDumbo/internal/party"
	"sDumbo/pkg/config"
	"sDumbo/pkg/core"
	"sDumbo/pkg/utils/logger"
	"strconv"
	"time"

	"github.com/360EntSecGroup-Skylar/excelize"
)

func main() {
	B, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Fatalln(err)
	}

	c, err := config.NewConfig("./config.yaml", true)
	if err != nil {
		fmt.Println(err)
	}
	logg := logger.NewLoggerWithID("config", c.PID)
	tssConfig := config.TSSconfig{}
	err = tssConfig.UnMarshal(c.TSSconfig)
	if err != nil {
		logg.Fatalf("fail to unmarshal tssConfig: %s", err.Error())
	}
	tseConfig := config.TSEconfig{}
	err = tseConfig.UnMarshal(c.TSEconfig)
	if err != nil {
		logg.Fatalf("fail to unmarshal tseConfig: %s", err.Error())
	}

	p := party.NewHonestParty(uint32(c.N), uint32(c.F), uint32(c.PID), c.IPList, c.PortList, tssConfig.Pk, tssConfig.Sk, tseConfig.Pk, tseConfig.Vk, tseConfig.Sk)
	p.InitReceiveChannel()

	time.Sleep(time.Second * time.Duration(c.PrepareTime))

	p.InitSendChannel()

	txlength := 250
	inputChannel := make(chan []byte, 1024)
	outputChannel := make(chan []byte, 1024)

	if B == 0 {
		B = c.N
	}

	data := make([]byte, txlength*B/c.N)
	rand.Read(data)

	st := time.Now()
	log.Println("start consensus for B=", B)
	resultLen := 0
	go aab.MainProcess(p, inputChannel, outputChannel)
	for e := 1; e <= c.TestEpochs; e++ {
		inputChannel <- data
		value := <-outputChannel
		resultLen += len(value)
	}

	txNums := resultLen / txlength
	lantency := time.Since(st).Seconds()
	core.Mu.Lock()
	traffic := core.Traffic
	core.Mu.Unlock()

	titleList := []string{"ID", "txNums", "Lantency", "Traffic"}
	f := excelize.NewFile()
	f.SetSheetRow("Sheet1", "A1", &titleList)
	f.SetSheetRow("Sheet1", "A2", &[]interface{}{p.PID, txNums, lantency, traffic})
	if err := f.SaveAs("statistic.xlsx"); err != nil {
		log.Fatal(err)
	}

	time.Sleep(time.Second * time.Duration(c.WaitTime))
}
