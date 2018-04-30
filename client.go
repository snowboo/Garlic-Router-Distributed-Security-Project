package main

import (
    "os"
    "fmt"
    "./nodelib"
    "strconv"
)

func main() {
    args := os.Args[1:]

	if len(args) != 3 {
		fmt.Println("Usage go run client.go [nodeAddr] [nodeID] [pseudonymKey]")
        return
	}

    nodeInstance := nodelib.StartNode()
    nodeID, err := strconv.Atoi(args[1])

    message := "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed dictum sem sapien, sit amet consectetur ligula cursus id. Maecenas placerat dictum nulla nec consectetur. Nulla mattis tellus sollicitudin nibh vulputate vulputate et vitae turpis. Aliquam magna risus, viverra vitae dictum sit amet, finibus sit amet diam. Vivamus maximus ex ac odio semper gravida. Praesent tempor libero vitae metus elementum, at suscipit turpis mattis. Proin sapien neque, venenatis eu mi non, tincidunt vehicula nunc. Mauris eget turpis diam. Vivamus et ipsum sed eros eleifend ullamcorper. Aenean accumsan sodales ipsum nec pretium. Aliquam in malesuada lorem. Integer tincidunt tempus lacus, ac efficitur nisi."
    if err == nil {
        err = nodeInstance.SendMessage(args[0], []int{nodeID}, []string{args[2]}, []string{message}, true)
        // if timeout try sending message again, this is our way of dealing with errors in the network
        for {
            if err != nil {
                err = nodeInstance.SendMessage(args[0], []int{nodeID}, []string{args[2]}, []string{message}, true)
            } else {
                break
            }
        }
    }
} // main
