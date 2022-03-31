package find

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"xrkRce/rce"
)

func parsePortsToScan(portsFlag string) ([]int, error) {
	p, err := strconv.Atoi(portsFlag)
	if err == nil {
		return []int{p}, nil
	}

	ports := strings.Split(portsFlag, "-")
	if len(ports) != 2 {
		return nil, errors.New("unable to determine port(s) to scan")
	}

	minPort, err := strconv.Atoi(ports[0])
	if err != nil {
		return nil, fmt.Errorf("failed to convert %s to a valid port number", ports[0])
	}

	maxPort, err := strconv.Atoi(ports[1])
	if err != nil {
		return nil, fmt.Errorf("failed to convert %s to a valid port number", ports[1])
	}

	if minPort <= 0 || maxPort <= 0 {
		return nil, fmt.Errorf("port numbers must be greater than 0")
	}

	var results []int
	for p := minPort; p <= maxPort; p++ {
		results = append(results, p)
	}
	return results, nil
}

func worker(host string, portsChan <-chan int, resultsChan chan<- int) {
	for p := range portsChan {
		address := fmt.Sprintf("%s:%d", host, p)
		conn, err := net.Dial("tcp", address)
		if err != nil {
			//fmt.Printf("%d CLOSED (%s)\n", p, err)
			resultsChan <- 0
			continue
		}
		conn.Close()
		resultsChan <- p
	}
}

func printResults(ports []int) {
	sort.Ints(ports)
	//fmt.Println("\nResults\n--------------")
	for _, p := range ports {
		//fmt.Println("%d - open\n", p)
		pp := strconv.Itoa(p)
		rce.GetWebInfo(pp)
	}
}
