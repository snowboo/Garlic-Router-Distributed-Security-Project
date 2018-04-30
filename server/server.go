// DISCLAIMER: This code was based on the instructors' code from Project 1

package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/rpc"
	"os"
	"strconv"
	"sync"
	"time"

	"../shared"
	// TODOTINA
	// "bitbucket.org/bestchai/dinv/instrumenter"

	// TODO: FRANCES
	// "../glog"
	"github.com/DistributedClocks/GoVector/govec"
)

type UnknownKeyError error

type KeyAlreadyRegisteredError string

func (e KeyAlreadyRegisteredError) Error() string {
	return fmt.Sprintf("Server: key already registered [%s]", string(e))
}

type AddressAlreadyRegisteredError string

func (e AddressAlreadyRegisteredError) Error() string {
	return fmt.Sprintf("Server: address already registered [%s]", string(e))
}

type RServer int

type Node struct {
	Address         net.Addr
	RecentHeartbeat int64
}

type AllNodes struct {
	sync.RWMutex
	all map[string]*Node
}

// ****************************** Global Variables ******************************
var (
	unknownKeyError   UnknownKeyError = errors.New("Server: unknown key")
	heartBeatInterval                 = 2000

	outLog *log.Logger = log.New(os.Stderr, "[serv] ", log.Lshortfile|log.LUTC|log.Lmicroseconds)
	// Nodes in the system
	allNodes    AllNodes = AllNodes{all: make(map[string]*Node)}
	tunnelCount          = 0
	nodeCount            = 0

	Logger     *govec.GoLog
	ownUDPPort string
)

// ****************************** End Global Variables ******************************

func (s *RServer) Register(client *shared.RegisterNode, heartbeat *int) (err error) {
	go shivReceive(ownUDPPort, "Server received registration from node", "Server is sending message to node that it successfully registered")
	allNodes.Lock()
	defer allNodes.Unlock()

	key := publicKeyToString(client.RouterPubKey)

	if _, exists := allNodes.all[key]; exists {
		return KeyAlreadyRegisteredError(client.NodeIp)
	}

	for _, node := range allNodes.all {
		if node.Address.String() == client.NodeIp {
			return AddressAlreadyRegisteredError(client.NodeIp)
		}
	}

	*heartbeat = heartBeatInterval
	addr, _ := net.ResolveTCPAddr("tcp", client.NodeIp)

	allNodes.all[key] = &Node{
		addr,
		time.Now().UnixNano(),
	}

	go monitor(key, time.Duration(heartBeatInterval)*time.Millisecond)

	outLog.Printf("Got Register from %s\n", client.NodeIp)

	return nil
} // Register

func (s *RServer) GetAllNodes(_ignored *bool, nodes *map[string]string) (err error) {
	allNodes.RLock()
	defer allNodes.RUnlock()

	temp := make(map[string]string)

	for pubKey, node := range allNodes.all {
		temp[pubKey] = node.Address.String()
	}

	*nodes = temp
	return nil
} // GetAllNodes

func (s *RServer) Heartbeat(routerPubKey *rsa.PublicKey, _ignored *bool) (err error) {
	allNodes.Lock()
	defer allNodes.Unlock()

	key := publicKeyToString(routerPubKey)

	if _, ok := allNodes.all[key]; !ok {
		return unknownKeyError
	}

	allNodes.all[key].RecentHeartbeat = time.Now().UnixNano()
	return nil
} // Heartbeat

func (s *RServer) GenerateTunnelID(_ignored *bool, tunnelID *int) (err error) {
	*tunnelID = tunnelCount
	outLog.Printf("Generated tunnel ID %d\n", *tunnelID)
	tunnelCount++
	return nil
} // GenerateTunnelID

func (s *RServer) GenerateNodeID(_ignored *bool, nodeID *int) (err error) {
	*nodeID = nodeCount
	nodeCount++
	return nil
} // GenerateTunnelID

func main() {
	rserver := new(RServer)

	server := rpc.NewServer()
	server.Register(rserver)

	addrs, _ := net.InterfaceAddrs()
	ln, _ := net.Listen("tcp", ":0")

	Logger = govec.InitGoVector("server", "server")
	var buf []byte
	Logger.PrepareSend("[Server] - Setup is complete for server", buf)

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				serverIpPort := ipnet.IP.String() + ":" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
				outLog.Printf("Server started. Receiving on %v\n", serverIpPort)
				break
			}
		}
	}

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ownUDPPort = ipnet.IP.String() + ":" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
				outLog.Printf("Server UDP port is %v\n", ownUDPPort)
				break
			}
		}
	}

	for {
		conn, _ := ln.Accept()
		go server.ServeConn(conn)
	}
} // main

// Function to delete dead node (no recent heartbeat)
func monitor(key string, heartBeatInterval time.Duration) {
	for {
		allNodes.Lock()
		if time.Now().UnixNano()-allNodes.all[key].RecentHeartbeat > int64(heartBeatInterval) {
			outLog.Printf("%s timed out\n", allNodes.all[key].Address.String())
			delete(allNodes.all, key)
			allNodes.Unlock()
			return
		}
		outLog.Printf("%s is alive\n", allNodes.all[key].Address.String())
		allNodes.Unlock()
		time.Sleep(heartBeatInterval)
	}
} // monitor

func publicKeyToString(pubkey *rsa.PublicKey) string {
	publicKeyBytes, _ := x509.MarshalPKIXPublicKey(pubkey)
	return hex.EncodeToString(publicKeyBytes)
} //publicKeyToString

func shivReceive(listen, send_text, receive_text string) {
	conn, err := net.ListenPacket("udp", listen)
	if err != nil {
		return
	}

	var buf [512]byte
	n := 1

	_, addr, err := conn.ReadFrom(buf[0:])
	var incommingMessage int
	Logger.UnpackReceive(receive_text, buf[0:], &incommingMessage)
	fmt.Printf("Received %d\n", incommingMessage)
	if err != nil {
		return
	}

	outBuf := Logger.PrepareSend(send_text, n)
	conn.WriteTo(outBuf, addr)
	conn.Close()
} // shivReceive

func checkError(err error) {
	if err != nil {
		outLog.Println("Error is: ", err.Error())
	}
} //checkError
