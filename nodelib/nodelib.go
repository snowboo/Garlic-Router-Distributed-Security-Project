package nodelib

import (
    "fmt"
    "net/rpc"
    "../shared"
)

type TimeOutError string
func (e TimeOutError) Error() string {
	return fmt.Sprintf("Node has timed out: [%s]", string(e))
}

type NodeStruct struct {
}

type Node interface {
    SendMessage(nodeAddr string, nodeID []int, pseudoPubKey []string, message []string, needsReply bool) (err error)
}


func(node NodeStruct) SendMessage(nodeAddr string, nodeID []int, pseudoPubKey []string, message []string, needsReply bool) (err error){
    args := shared.MessageRPC{NodeID: nodeID, PseudoPubKey: pseudoPubKey, Message: message, NeedsReply: needsReply}
    var reply bool
    nodeRPC, err := rpc.Dial("tcp", nodeAddr)
    if err == nil {
        fmt.Println("Trying to send message now.")
        err = nodeRPC.Call("NodeRPC.SendMessageRPC", &args, &reply)
        if err != nil {
            fmt.Println("The sender node is dead. Try sending from different node.")
            return nil
        } else {
            nodeRPC.Close()
            if !reply {
                return TimeOutError("SendMessage")
            } else {
                fmt.Println("The message is sent successfully.")
                return nil
            }
        }
    }
    fmt.Println(err)
    return nil
} // SendMessage

func StartNode() (node Node) {
    nodeInstance := NodeStruct{}

    return nodeInstance
} // StartNode
