package main

import (
	"net"
	"encoding/json"
	"fmt"
	"os"
)

var localHost = "localhost"

func main() {
	args := os.Args[1:]

	if len(args) != 1 {
		fmt.Println("Usage go run node.go [tcpPort]")
		return
	}

	port := args[0]


	fmt.Println("Starting test message")

	conn, _ := net.Dial("tcp", localHost + ":" + port)

	SendTCPMessage(conn)
	fmt.Println("Finished test message")

	conn.Close()
}


func SendTCPMessage(conn net.Conn) {
	msg := "hello"
	jsonMsg, _ := json.Marshal(msg)

	buf := make([]byte, 1024)


	conn.Write(jsonMsg)
	fmt.Println("Wrote test message")


	size, _ := conn.Read(buf)
	fmt.Println("Read test message reply")

	buf = buf[:size]
	fmt.Println(string(buf))


}