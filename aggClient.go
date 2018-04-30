package main

import (
    "os"
    "fmt"
    "./nodelib"
    "strconv"
)

func main() {
    args := os.Args[1:]

	if len(args) != 5 {
		fmt.Println("Usage go run client.go [nodeAddr] [nodeID] [pseudonymKey] [nodeID] [pseudonymKey]")
        return
	}

    nodeInstance := nodelib.StartNode()
    nodeID, err := strconv.Atoi(args[1])
    nodeID2, err := strconv.Atoi(args[3])

    message := "Hello, can you hear me?"
    message2 := "Hello from the other side!"
    if err == nil {
        err = nodeInstance.SendMessage(args[0], []int{nodeID, nodeID2}, []string{args[2], args[4]}, []string{message, message2}, true)
        // if timeout try sending message again, this is our way of dealing with errors in the network
        for {
            if err != nil {
                err = nodeInstance.SendMessage(args[0], []int{nodeID, nodeID2}, []string{args[2], args[4]}, []string{message, message2}, true)
            } else {
                break
            }
        }
    }
} // main
