package find

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func RootScan(ip string, port string,x int) {

	//flag.Parse()

	var openPorts []int

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		printResults(openPorts)
		os.Exit(0)
	}()

	portsToScan, err := parsePortsToScan(port)
	if err != nil {
		fmt.Printf("Failed to parse ports to scan: %s\n", err)
		os.Exit(1)
	}

	portsChan := make(chan int, x)
	resultsChan := make(chan int)

	for i := 0; i < cap(portsChan); i++ { // numWorkers also acceptable here
		go worker(ip, portsChan, resultsChan)
	}

	go func() {
		for _, p := range portsToScan {
			portsChan <- p
		}
	}()

	for i := 0; i < len(portsToScan); i++ {
		if p := <-resultsChan; p != 0 { // non-zero port means it's open
			openPorts = append(openPorts, p)
		}
	}

	close(portsChan)
	close(resultsChan)
	printResults(openPorts)
}
