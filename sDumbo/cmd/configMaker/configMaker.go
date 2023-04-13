package main

import (
	"fmt"
	"log"
	"sDumbo/pkg/config"
)

func main() {
	c, err := config.NewConfig("./config.yaml", true)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(c.N)
	c.RemoteGen("./configs")
}
