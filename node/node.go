// go run node/node.go 308204a30201000282010100cbeaceffef3d983472fcbe353312867adafd437e3dfde2639443f2a2b082d1d4c2eeed3fd3b8a28b88971e6adabaaa5aa7a454bae0242ff4e5441e507fb1b4addd540cc1f92752f1488919ae77b0f54cb033fb74f5e2b14eb8297aeafd4a8c59f9a204e77d2b711e8c2d6f88245133fc49dafaf4b68bf31b1f286eb85724bf0c059ffe013e6cc3f9968805dabef68c0df658c687288fc1aaa7710e5e42c787ecf07a8d0e590c4b4dda9af655314ef82ad88709ccd70c407cc7d066449896528cb18a9eb2a45ed0967144c2d2bf0312f445a5d16d8fd97032b626f3d0dc04e7c3577f57f900bd3876322b9b52472f2592ced3fe5d9ba372005e2ace32534c18ed0203010001028201006c109cf09f2daa3aa9716dafadc8348269096cba3b4a0faeac053251ab6f389a2350116510e3b9286f137ee82bd05eb53a406932bbd411a21bd9f4a2be7943821c580d86c26e67933cd88346a5619f2dabf7705c346e957e5d348652803700983225fda95bf928b282a11589358ddf19e55dea3ec37af933b7586b0cc009d6402b85586af7508b51bb5e201188d9f7037f3b6ba1e52ec5cf44a6e5c84569752ba98d87d1f90b894c5f38526ef9a4329cf1a231756fa9dfe01c0f74eee59968caf045f25835e5295cc81aac776956713074242ff224dce1888dc33ab2fdb1cb69d67d5af7de0f512445d012a386b02124a245a9a2d090a556173e481e4042a8e102818100df83e90bed29d19fd7cd7e3c457bbc641f761cc1a45e2e36460347816da9ae3838912f6503a55fd3c8f4cb9f00d4e54c2eda1ca6f3e235180ba25e26c2a65aa8a0f37ce8f77fd2acd2d72fe1fab1deae6025a9ea1a9706b67cdf05cbd1937dd157797f1ea45a01a91c5acc87ca443a921e9e79c60877d2779128578811b602e902818100e98dbc1b510b430f6efdab1cd3e5344ba130512600d8945113e84edccf16d4389807e6a1c1dc927b16f55af970f4df23b63fd231f98c27b2b0c99c304da764252fc16a1c3a5e41ac8c15f575b5e4b33b1697fbe3ce1257df74dca28fd160f9d242f4f6d9dde885f9b1c83984890d80efc8a074c7253abfc315fe6fb3f5ff7b65028180371b70b3ce0f476d9f693cbc636d346f830a3de0c843a8251d71e589559e4623fa5e614f086d178941bc890f74c7089995db94c0dcd462bec0ef9143012ebe9f60bf678690aee52452ff5700e22c4478bd9fcb9aba5f8dfa2423606c76096535ddd948ac275d41978e341cc545eb387d9a2afc5f04eb75eaa0d14f736eda6f3102818014ad319c117eb7bf240a5d1dbe3caa768f9ca17285dca6b4ced86032f83a832b477a5b96b27cfe92db23799c5fbdae0b9154f11cef84d2f6e4e3d46a0a55e96dc95e8c30579284a9ebf4fdb820145131c7fc48969065db55b318dd63721bedc2099f7a432b7c2c7040a7034092899982a0f663a045d17fac9bc3dccbc7d9886902818100821b2ae12c89007c2466aa9e07b4fced2d083679286bd57f562b01dd50dcbb8c2a36ca9fb0bdee9c88e84ba4bf1086d32a59234345d814edb3ff5a60e5039ce1da26adbd2580f3696a5cf129a69b7dd39a083fba999024bf75e4485fc46a0bfc81f3e1d12ca850ec96d9409fc9ef52f042273173476f95eb232332c3447ada91 206.87.217.134:62389 9000

package main

import (
	"../shared"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"net"
	"net/rpc"
	"os"
	"strconv"
	"sync"
	"time"
	// TODO: FRANCES
	// distclock "github.com/DistributedClocks/GoVector/govec"
	"github.com/arcaneiceman/GoVector/govec"
	// TODOTINA
	// "bitbucket.org/bestchai/dinv/instrumenter"
)

////////////////////////////////////////////////////////////////////////////////////////////
// Struct with locks
type GatewayMap struct {
	sync.RWMutex
	allGateways map[int]shared.TunnelGatewayInfo
}

type TunnelMap struct {
	sync.RWMutex
	allTunnels map[int]shared.TunnelInfo
}

type OwnedTunnelMap struct {
	sync.RWMutex
	allTunnels map[int]shared.TunnelNodes
}

type PseudonymKeysMap struct {
	sync.RWMutex
	allPseudonymKeys map[int]string
}

type AesKeysMap struct {
	sync.RWMutex
	allAesKeys map[int]*[32]byte
}

// ****************************** Global Variables ******************************

var ownPseudoPrivKey *rsa.PrivateKey
var ownRouterPrivKey *rsa.PrivateKey
var ownID int
var ownAddress = ""
var outLog = log.New(os.Stderr, "[node] ", log.Lshortfile|log.LUTC|log.Lmicroseconds)
var serverRPC *rpc.Client
var tunnelLength = 3
var inboundTunnelID int
var address = ""

// TODO: FRANCES - LOGGER
var Logger *govec.GoLog
var ownUDPIpPort string
var serverUDPPort string

// map of inbound tunnel infomation of other node
var gatewayMap GatewayMap = GatewayMap{allGateways: make(map[int]shared.TunnelGatewayInfo)}

// map of tunnel that this node is part of
var tunnelMap TunnelMap = TunnelMap{allTunnels: make(map[int]shared.TunnelInfo)}

// map of tunnel that this node created
var ownedTunnelMap OwnedTunnelMap = OwnedTunnelMap{allTunnels: make(map[int]shared.TunnelNodes)}

// map of node pseudonym keys and node ids
var pseudonymKeys PseudonymKeysMap = PseudonymKeysMap{allPseudonymKeys: make(map[int]string)}

// map of node aes keys and pseudonym keys, node-node aes key
var aesKeys AesKeysMap = AesKeysMap{allAesKeys: make(map[int]*[32]byte)}

// a timeout for reply
var messageReply = shared.MessageReply{WaitingForReply: 0}

// ****************************** End Global Variables ******************************

func AddNode(nodeID int, pseudonymKey string) {
	pseudonymKeys.Lock()
	pseudonymKeys.allPseudonymKeys[nodeID] = pseudonymKey
	pseudonymKeys.Unlock()

} // AddNode

type NodeRPC string

func (t *NodeRPC) SendMessageRPC(argsInput *shared.MessageRPC, success *bool) error {
	nodeID := argsInput.NodeID
	pseudoPubKeyStrings := argsInput.PseudoPubKey
	messages := argsInput.Message
	needsReply := argsInput.NeedsReply

	pseudoPubKeys := make([]*rsa.PublicKey, len(pseudoPubKeyStrings))
	for i, v := range pseudoPubKeyStrings {
		pseudoPubKey, err := publicKeyStringToKey(v)
		if err != nil {
			*success = false
			return nil
		}
		pseudoPubKeys[i] = pseudoPubKey
	}

	messageReply.WaitingForReply = 0
	*success = SendMessage(nodeID, pseudoPubKeys, messages, needsReply)

	return nil
} // SendMessageRPC

func SendMessage(nodeIDs []int, pseudoPubKeys []*rsa.PublicKey, messages []string, needsReply bool) (success bool) {
	// Need to perform series of encryptions on message before this
	tunnelId := createOutboundTunnel(tunnelLength)

	var messageToSend shared.Message
	var jsonMsg []byte
	tunnelGateways := make([]shared.TunnelGatewayInfo, len(nodeIDs))
	encryptedMsgs := make([][]byte, len(nodeIDs))

	for i := range nodeIDs {
		aesKeys.Lock()
		aesKey := aesKeys.allAesKeys[nodeIDs[i]]
		aesKeys.Unlock()
		tunnelGatewayInfo, success := getInboundGateway(nodeIDs[i])
		if !success {
			return false
		}
		tunnelGateways[i] = *tunnelGatewayInfo
		if aesKey == nil {
			aesKey, _ = generateAESKey()
			aesKeys.Lock()
			aesKeys.allAesKeys[nodeIDs[i]] = aesKey
			aesKeys.Unlock()
		}
		messageToSend = shared.Message{AESKey: aesKey, PseudonymPublicKey: "", MessageString: "", NodeID: ownID, NeedsReply: false}
		// Packaging the initial message up by encrypting the message with pseudonym public key
		// ==========
		// | message|
		// ==========
		jsonMsg, _ = json.Marshal(messageToSend)
		encryptedMsg, _ := encrypt(jsonMsg, pseudoPubKeys[i])
		encryptedMsgs[i] = encryptedMsg
	}

	sendEncryptedMessageHelper(tunnelGateways, encryptedMsgs, tunnelId)
	time.Sleep(time.Second)

	for i := range nodeIDs {
		aesKeys.Lock()
		aesKey := aesKeys.allAesKeys[nodeIDs[i]]
		aesKeys.Unlock()
		tunnelGatewayInfo, success := getInboundGateway(nodeIDs[i])
		if !success {
			return false
		}
		tunnelGateways[i] = *tunnelGatewayInfo
		messageToSend = shared.Message{AESKey: aesKey, PseudonymPublicKey: publicKeyToString(&ownPseudoPrivKey.PublicKey), MessageString: messages[i], NodeID: ownID, NeedsReply: needsReply}
		outLog.Println("Sending message '", messages[i], "' to node", nodeIDs[i], "using tunnel", tunnelId)
		// Packaging the initial message up by encrypting the message with aes key
		// ==========
		// | message|
		// ==========
		jsonMsg, _ = json.Marshal(messageToSend)
		encryptedMsg, _ := encryptAES(jsonMsg, aesKey)
		encryptedMsgs[i] = encryptedMsg
		if needsReply {
			messageReply.WaitingForReply += 1
		}
	}

	sendEncryptedMessageHelper(tunnelGateways, encryptedMsgs, tunnelId)

	if needsReply {
		for i := 0; i < 20; i++ {
			messageReply.Lock()
			if messageReply.WaitingForReply == 0 {
				messageReply.Unlock()
				return true
			}
			messageReply.Unlock()
			time.Sleep(500 * time.Millisecond)
		}
		return false
	}

	return true
}

func sendEncryptedMessageHelper(tunnelGatewayInfo []shared.TunnelGatewayInfo, encryptedMsg [][]byte, tunnelId int) (err error) {
	ownedTunnelMap.Lock()
	tunnelEndpointKey := ownedTunnelMap.allTunnels[tunnelId].TunnelEndpointKey
	ownedTunnelMap.Unlock()

	// Creation of a tunnel message that will be encrypted into a package
	// ==============================
	// | tunnelGatewayInfo | message|
	// ==============================
	infoPackages := make([]shared.InfoPackage, len(tunnelGatewayInfo))
	for i := range tunnelGatewayInfo {
		infoPackages[i] = shared.InfoPackage{tunnelGatewayInfo[i], encryptedMsg[i]}
	}
	infoPackageMsg, _ := json.Marshal(infoPackages)
	encryptedInfoPackage, _ := encryptAES(infoPackageMsg, tunnelEndpointKey)

	// Append tunnelId onto the package
	// =========================================
	// | tunnelId | tunnelGatewayInfo | message|
	// =========================================
	tunnelMap.Lock()
	tunnelKey := tunnelMap.allTunnels[tunnelId].TunnelKey
	tunnelMap.Unlock()
	finalPackage := shared.Package{tunnelId, encryptedInfoPackage}
	finalPackageMsg, _ := json.Marshal(finalPackage)
	encryptedFinalPackage, _ := encryptAES(finalPackageMsg, tunnelKey)

	ownedTunnelMap.Lock()
	nodesAddresses := ownedTunnelMap.allTunnels[tunnelId].NodesAddresses
	ownedTunnelMap.Unlock()

	// go shivizSend(ownUDPIpPort, nodesAddresses[1], "Sending message to another node", "Received that node got the message", infoPackageMsg)
	if ownAddress != nodesAddresses[1] {
		// check error
		conn, err := net.Dial("tcp", nodesAddresses[1])
		if err == nil {
			defer conn.Close()
			conn.Write(encryptedFinalPackage)
		}
	} else {
		// sending to myself
		receivedMessage(encryptedFinalPackage)
	}

	return err
} // sendEncryptedMessageHelper

func listenToConnection(tcpListener net.Listener) {
	// Read the incoming connection into the buffer.
	for {
		conn, err := tcpListener.Accept()
		if err != nil {
			outLog.Println("Error accepting: ", err.Error())
			os.Exit(1)
		}

		go handleConnection(conn)
	}
} // listenToConnection

func handleConnection(conn net.Conn) {
	buf := make([]byte, 8192)
	n, err := conn.Read(buf)

	if err != nil {
		outLog.Println("Error: ", err)
	} else {
		receivedMessage(buf[:n])
		conn.Close()
	}
} // handleConnection

func receivedMessage(message []byte) {
	var nextHopIp string
	var tunnelRole int
	var packageMessage shared.Package
	var err error

	// go shivReceive(ownUDPIpPort, "Received the message from other node", "Sending confirmation to other node that message is received")

	// CASE: tunnel map update message / delete messages
	err = json.Unmarshal(message, &packageMessage)
	if err == nil && packageMessage.TunnelID == shared.TUNNEL_MAP_FLOODING {
		var updateTunnelMapInfo shared.TunnelInfo
		err = json.Unmarshal(packageMessage.EncryptedData, &updateTunnelMapInfo)
		if err == nil {
			toDelete := updateTunnelMapInfo.TunnelRole == shared.TO_DELETE
			updateTunnelMap(updateTunnelMapInfo.TunnelID, updateTunnelMapInfo, toDelete)
			return
		}
	}

	// CASE: flooding message
	if err == nil && packageMessage.TunnelID == shared.FLOODING {
		receiveFloodingMessages(packageMessage.EncryptedData)
		return
	}

	// CASE: requesting gateway map
	if err == nil && packageMessage.TunnelID == shared.REQUEST_GATEWAY_MAP {
		sendGatewayMap(string(packageMessage.EncryptedData))
		return
	}

	// CASE: receiving gateway map
	if err == nil && packageMessage.TunnelID == shared.SEND_GATEWAY_MAP {
		gatewayMap.Lock()
		err = json.Unmarshal(packageMessage.EncryptedData, &gatewayMap.allGateways)
		gatewayMap.Unlock()
		return
	}

	var newMessage []byte
	tunnelMap.Lock()
	for _, tunnelInfo := range tunnelMap.allTunnels {
		key := tunnelInfo.TunnelKey
		newMessage, err = decryptAES(message, key)
		if err == nil {
			break
		}
	}
	tunnelMap.Unlock()

	if err != nil {
		message, err = decrypt(message, ownRouterPrivKey)
		if err == nil {
			var updateTunnelInfoMessage shared.UpdateTunnelInfoMessage
			err = json.Unmarshal(message, &updateTunnelInfoMessage)
			if err == nil {
				updateLocalGatewayMap(updateTunnelInfoMessage.NodeID, updateTunnelInfoMessage.GatewayInfo, false)
				return
			}
		}
	}

	err = json.Unmarshal(newMessage[:], &packageMessage)
	if err != nil {
		return
	}
	tunnelMap.Lock()
	tunnelInfo2 := tunnelMap.allTunnels[packageMessage.TunnelID]
	tunnelMap.Unlock()
	nextHopIp = tunnelInfo2.NextHopIp
	tunnelRole = tunnelInfo2.TunnelRole

	if err != nil {
		outLog.Println(err)
	} else {
		switch tunnelRole {
		case shared.GATEWAY:
			forwardMessage(packageMessage.TunnelID, packageMessage.EncryptedData, nextHopIp)
		case shared.PARTICIPANT:
			forwardMessage(packageMessage.TunnelID, packageMessage.EncryptedData, nextHopIp)
		case shared.ENDPOINT:
			forwardMessageEndpoint(packageMessage.TunnelID, packageMessage.EncryptedData)
		default:
		}
	}
} // receivedMessage

func forwardMessage(tunnelID int, message []byte, destinationIp string) {
	tunnelMap.Lock()
	tunnelInfo := tunnelMap.allTunnels[tunnelID]
	tunnelMap.Unlock()
	key := tunnelInfo.TunnelKey

	messagePackage := shared.Package{
		TunnelID:      tunnelID,
		EncryptedData: message,
	}

	messageMarshal, _ := json.Marshal(messagePackage)
	// encrypt message
	message, _ = encryptAES(messageMarshal, key)
	outLog.Println("Forwarding message on tunnel", tunnelID, "to", destinationIp)
	if destinationIp != ownAddress {
		conn, err := net.Dial("tcp", destinationIp)
		if err == nil {
			defer conn.Close()
			conn.Write(message)
			return
		}
	} else {
		receivedMessage(message)
	}
} // forwardMessageParticipant

func forwardMessageEndpoint(tunnelID int, message []byte) {
	tunnelMap.Lock()
	key := tunnelMap.allTunnels[tunnelID].TunnelEndpointKey // tunnelInfo instead of ownedTunnelMap[tunnelID]
	tunnelMap.Unlock()
	// check whether it is an inbound tunnel outbound endpoint
	// check for outbound endpoint
	if key != nil {
		message, err := decryptAES(message, key)
		var infoPackages []shared.InfoPackage
		err = json.Unmarshal(message[:], &infoPackages)
		if err != nil {
			return
		}

		for _, infoPackage := range infoPackages {
			tunnelGatewayInfo := infoPackage.GatewayInfo
			message = infoPackage.EncryptedData

			messagePackage := shared.Package{
				TunnelID:      tunnelGatewayInfo.TunnelID,
				EncryptedData: message,
			}

			messageMarshal, err := json.Marshal(messagePackage)
			newMessage, _ := encryptAES(messageMarshal, tunnelGatewayInfo.TunnelKey)
			if err == nil {
				if tunnelGatewayInfo.TunnelGatewayIP != ownAddress {
					conn, err := net.Dial("tcp", tunnelGatewayInfo.TunnelGatewayIP)
					if err == nil {
						defer conn.Close()
						conn.Write(newMessage)
					}
				} else {
					receivedMessage(newMessage)
				}
			}
		}
	} else {
		// check for inbound endpoint
		newMessage, err := decrypt(message, ownPseudoPrivKey)
		if err == nil { // this is a key message
			var messageStruct shared.Message
			err = json.Unmarshal(newMessage[:], &messageStruct)
			if err == nil && messageStruct.MessageString == "" {
				outLog.Println("AESKey received", messageStruct.AESKey, "from node", messageStruct.NodeID)
				aesKeys.Lock()
				aesKeys.allAesKeys[messageStruct.NodeID] = messageStruct.AESKey
				aesKeys.Unlock()
			}
		} else { // this is an actual message
			// decrypt with aes key
			aesKeys.Lock()
			tempAesKeyMap := aesKeys.allAesKeys
			aesKeys.Unlock()
			for id, aesKey := range tempAesKeyMap {
				newMessage, err = decryptAES(message, aesKey)
				if err == nil {
					var messageStruct shared.Message
					err = json.Unmarshal(newMessage[:], &messageStruct)
					if err == nil {
						outLog.Println("Received the message '", messageStruct.MessageString, "' from node", id)
						if messageStruct.NeedsReply {
							key, err := publicKeyStringToKey(messageStruct.PseudonymPublicKey)
							if err == nil {
								outLog.Println("Sending reply to node", id)
								ids := []int{id}
								keys := []*rsa.PublicKey{key}
								replies := []string{"reply"}
								AddNode(messageStruct.NodeID, messageStruct.PseudonymPublicKey)
								SendMessage(ids, keys, replies, false)
							}
						} else {
							if messageStruct.MessageString == "reply" {
								messageReply.Lock()
								messageReply.WaitingForReply -= 1
								messageReply.Unlock()
							}
						}
					}
					break
				}
			}
		}
	}
} // forwardMessageEndpoint

func createOutboundTunnel(tunnelLength int) int {
	// The current node will be the tunnel outbound gateway
	tunnelID, _, _ := createTunnelHelper(tunnelLength, false)
	ownedTunnelMap.Lock()
	outLog.Println("Created outbound tunnel", tunnelID, "with following nodes:", ownedTunnelMap.allTunnels[tunnelID].NodesAddresses)
	ownedTunnelMap.Unlock()
	return tunnelID
} // createOutboundTunnel

func createInboundTunnel(tunnelLength int) int {
	// The current node will be an inbound tunnel endpoint
	tunnelID, tunnelGatewayIP, tunnelKey := createTunnelHelper(tunnelLength, true)

	ownedTunnelMap.Lock()
	outLog.Println("Created inbound tunnel", tunnelID, "with following nodes:", ownedTunnelMap.allTunnels[tunnelID].NodesAddresses)
	ownedTunnelMap.Unlock()

	// updateGatewayMap
	gatewayInfo := shared.TunnelGatewayInfo{TunnelID: tunnelID, TunnelGatewayIP: tunnelGatewayIP, TunnelKey: tunnelKey}
	updateGatewayMap(ownID, gatewayInfo, false)

	return tunnelID
} // createInboundTunnel

func createTunnelHelper(tunnelLength int, isInbound bool) (int, string, *[32]byte) {
	// Ask server to generate tunnelID
	var _ignored bool
	var tunnelID int
	serverRPC.Call("RServer.GenerateTunnelID", &_ignored, &tunnelID)
	// Call GetAllNodes() on the server.
	nodes := make(map[string]string)
	serverRPC.Call("RServer.GetAllNodes", &_ignored, &nodes)
	// Randomly choose nodes obtained as tunnel participants
	keys := make([]string, 0)
	for k := range nodes {
		keys = append(keys, k)
	}
	tunnelNodeList := make([]*rsa.PublicKey, tunnelLength)
	tunnelNodeAddressesList := make([]string, tunnelLength)
	if !isInbound {
		tunnelNodeList[0] = &ownRouterPrivKey.PublicKey
		tunnelNodeAddressesList[0] = nodes[publicKeyToString(tunnelNodeList[0])]
		// Random generator
		mrand.Seed(time.Now().Unix())
		for i := 1; i < tunnelLength; i++ {
			randomKey := keys[mrand.Intn(len(keys))]
			tunnelNodeList[i], _ = publicKeyStringToKey(randomKey)
			tunnelNodeAddressesList[i] = nodes[randomKey]
		}
	} else {
		tunnelNodeList[tunnelLength-1] = &ownRouterPrivKey.PublicKey
		tunnelNodeAddressesList[tunnelLength-1] = nodes[publicKeyToString(tunnelNodeList[tunnelLength-1])]
		// Random generator
		mrand.Seed(time.Now().Unix())
		for i := 0; i < tunnelLength-1; i++ {
			randomKey := keys[mrand.Intn(len(keys))]
			tunnelNodeList[i], _ = publicKeyStringToKey(randomKey)
			tunnelNodeAddressesList[i] = nodes[randomKey]
		}
	}

	// Contact each chosen node to set their tunnelInfo in their tunnelMaps
	tunnelKey, _ := generateAESKey()
	tunnelEndpointKey, _ := generateAESKey()
	ownedTunnelMap.Lock()
	ownedTunnelMap.allTunnels[tunnelID] = shared.TunnelNodes{IsInbound: false, TunnelKey: tunnelKey, TunnelEndpointKey: tunnelEndpointKey, NodesRouterKeys: tunnelNodeList, NodesAddresses: tunnelNodeAddressesList}
	ownedTunnelMap.Unlock()

	var thisTunnelInfo shared.TunnelInfo
	for i := range tunnelNodeList {
		var otherTunnelInfo shared.TunnelInfo
		if i == 0 && !isInbound { // outbound tunnel gateway
			thisTunnelInfo = shared.TunnelInfo{TunnelID: tunnelID, TunnelRole: 0, NextHopIp: tunnelNodeAddressesList[i+1], TunnelKey: tunnelKey}
		} else if i == len(tunnelNodeList)-1 && isInbound { // inbound tunnel endpoint
			thisTunnelInfo = shared.TunnelInfo{TunnelID: tunnelID, TunnelRole: 2, NextHopIp: "", TunnelKey: tunnelKey}
		} else {
			if i == 0 { // gateway
				otherTunnelInfo = shared.TunnelInfo{TunnelID: tunnelID, TunnelRole: 0, NextHopIp: tunnelNodeAddressesList[i+1], TunnelKey: tunnelKey}
			} else if i == len(tunnelNodeList)-1 { // endpoint
				otherTunnelInfo = shared.TunnelInfo{TunnelID: tunnelID, TunnelRole: 2, NextHopIp: "", TunnelKey: tunnelKey, TunnelEndpointKey: tunnelEndpointKey}
			} else { // participant
				otherTunnelInfo = shared.TunnelInfo{TunnelID: tunnelID, TunnelRole: 1, NextHopIp: tunnelNodeAddressesList[i+1], TunnelKey: tunnelKey}
			}
			jsonMsg, _ := json.Marshal(otherTunnelInfo)
			jsonMsg, _ = json.Marshal(shared.Package{TunnelID: shared.TUNNEL_MAP_FLOODING, EncryptedData: jsonMsg})
			if tunnelNodeAddressesList[i] != ownAddress {
				conn, err := net.Dial("tcp", tunnelNodeAddressesList[i])
				if err == nil {
					conn.Write(jsonMsg)
				} else {
					outLog.Println("Error with connecting to", tunnelNodeAddressesList[i], "because", err)
				}
			} else {
				updateTunnelMap(tunnelID, otherTunnelInfo, false)
			}
		}
	}

	// updateTunnelMap
	updateTunnelMap(tunnelID, thisTunnelInfo, false)

	return tunnelID, tunnelNodeAddressesList[0], tunnelKey
} // createTunnelHelper

func deleteOutboundTunnel(tunnelID int) {
	deleteTunnelHelper(tunnelID)
} // deleteOutboundTunnel

func deleteInboundTunnel(tunnelID int) {
	deleteTunnelHelper(tunnelID)

	// updateGatewayMap
	updateGatewayMap(ownID, shared.TunnelGatewayInfo{}, true)
} // deleteInboundTunnel

func deleteTunnelHelper(tunnelID int) {
	// Contact each node in the tunnel to delete the tunnel from their tunnelMap
	ownedTunnelMap.Lock()
	addresses := ownedTunnelMap.allTunnels[tunnelID].NodesAddresses
	tunnelKey := ownedTunnelMap.allTunnels[tunnelID].TunnelKey
	ownedTunnelMap.Unlock()
	for _, addr := range addresses {
		tunnelInfo := shared.TunnelInfo{TunnelID: tunnelID, TunnelRole: shared.TO_DELETE, NextHopIp: "", TunnelKey: tunnelKey}
		jsonMsg, _ := json.Marshal(tunnelInfo)
		jsonMsg, _ = json.Marshal(shared.Package{TunnelID: shared.TUNNEL_MAP_FLOODING, EncryptedData: jsonMsg})
		if addr != ownAddress {
			conn, err := net.Dial("tcp", addr)
			if err == nil {
				conn.Write(jsonMsg) // contacted the node successfully
			} else {
				outLog.Println("Error with deleting tunnel flooding ", err)
			}
		} else {
			updateTunnelMap(tunnelID, shared.TunnelInfo{}, true)
		}
	}
	// updateTunnelMap
	updateTunnelMap(tunnelID, shared.TunnelInfo{}, true)
}

// ****************************** MESSAGE FLOODING ******************************
func getInboundGateway(nodeID int) (tunnel *shared.TunnelGatewayInfo, success bool) {
	// just take the gateway info from gateway map
	gatewayMap.Lock()
	defer gatewayMap.Unlock()
	if tunnelGatewayInfo, exist := gatewayMap.allGateways[nodeID]; exist {
		if tunnelGatewayInfo.TunnelKey == nil {
			return nil, false
		}
		return &tunnelGatewayInfo, true
	} else {
		return nil, false
	}
} // getInboundGateway

func updateGatewayMap(nodeID int, gatewayInfo shared.TunnelGatewayInfo, isDelete bool) {
	// update the local gatewayMap
	updateLocalGatewayMap(nodeID, gatewayInfo, isDelete)
	// do the flooding thing to let all nodes know
	// 1. get all nodes from server
	// Call GetAllNodes() on the server.
	var _ignored bool
	allNodes := make(map[string]string)
	serverRPC.Call("RServer.GetAllNodes", &_ignored, &allNodes)
	// 2. pick the first node as the relay node, all other nodes will be receiver
	// 3. for each of the other nodes, make message packet
	keys := make([]string, 0, len(allNodes))
	for k := range allNodes {
		keys = append(keys, k)
	}

	// message = tunnelGateWayInfoMessage + Pseudonym key
	// and encrypt inner message layer with receiver's router key
	message := shared.UpdateTunnelInfoMessage{NodeID: nodeID, GatewayInfo: gatewayInfo}
	mMessage, _ := json.Marshal(message)

	var relayNodeIPAddress string
	var relayNodeKey string
	for i, nodeRouterKey := range keys {
		if i == 0 {
			relayNodeIPAddress = allNodes[nodeRouterKey]
			relayNodeKey = nodeRouterKey
		} else {
			currNodeIPAddress := allNodes[nodeRouterKey]
			routerKey, _ := publicKeyStringToKey(nodeRouterKey)
			eMessage, err := encrypt(mMessage, routerKey)
			if err != nil {
				outLog.Print("Error from encryption - updateGatewayMap (1)")
			}
			// 4. Add layer to message: shared.FLOODING for tunnelID, IP address of receiver for tunnelGatewayIP, nil for tunnelPubKey
			layeredMessage := shared.InfoPackage{GatewayInfo: shared.TunnelGatewayInfo{TunnelID: shared.FLOODING, TunnelGatewayIP: currNodeIPAddress, TunnelKey: nil}, EncryptedData: eMessage}
			// 5. Encrypt with relay node's router key
			mlayeredMessage, err := json.Marshal(layeredMessage)
			thirdLayerMessage := shared.Package{TunnelID: shared.FLOODING, EncryptedData: mlayeredMessage}
			mThirdLayerMessage, err := json.Marshal(thirdLayerMessage)

			if err != nil {
				outLog.Println("Error from encryption - updateGatewayMap (2)")
			}
			// 6. send packets to relay node, and relay will send to receivers
			if relayNodeIPAddress != ownAddress {
				conn, err := net.Dial("tcp", relayNodeIPAddress)
				if err == nil {
					conn.Write(mThirdLayerMessage)
				} else {
					outLog.Println("TCP conn error - updateGatewayMap")
				}
			} else {
				receivedMessage(mThirdLayerMessage)
			}
		}
	}

	// this is sending back to the sender node
	if len(keys) > 1 && relayNodeIPAddress != ownAddress {
		receiverNodeIPAddress := relayNodeIPAddress
		receiverNodeRouterKey, _ := publicKeyStringToKey(relayNodeKey)

		for _, nodeRouterKey := range keys {
			if allNodes[nodeRouterKey] != relayNodeIPAddress {
				relayNodeIPAddress = allNodes[nodeRouterKey]
			}
		}

		eMessage, err := encrypt(mMessage, receiverNodeRouterKey)
		if err != nil {
			outLog.Println("Error from encryption - updateGatewayMap (1)")
		}
		layeredMessage := shared.InfoPackage{GatewayInfo: shared.TunnelGatewayInfo{TunnelID: shared.FLOODING, TunnelGatewayIP: receiverNodeIPAddress, TunnelKey: nil}, EncryptedData: eMessage}
		mlayeredMessage, err := json.Marshal(layeredMessage)
		thirdLayerMessage := shared.Package{TunnelID: shared.FLOODING, EncryptedData: mlayeredMessage}
		mThirdLayerMessage, err := json.Marshal(thirdLayerMessage)
		if err != nil {
			outLog.Println("Error from encryption - updateGatewayMap (2)")
		}
		if relayNodeIPAddress != ownAddress {
			conn, err := net.Dial("tcp", relayNodeIPAddress)
			if err == nil {
				defer conn.Close()
				conn.Write(mThirdLayerMessage)
			} else {
				outLog.Println("TCP conn error - updateGatewayMap")
			}
		} else {
			receivedMessage(mThirdLayerMessage)
		}
	}
}

func receiveFloodingMessages(message []byte) {
	// the node checks the messages they receive
	// the messageType = shared.FLOODING, then it is a flooding message
	// the input message needs to be processed:
	// 1. decrypt with the node's router key - the decryped message should be a shared.InfoPackage message
	// 2. Unmarshal the message
	// shared.InfoPackage{GatewayInfo: shared.TunnelGatewayInfo{TunnelID: 0, TunnelGatewayIP: currNodeIPAddress, TunnelPublicKey: nil}, EncryptedData: eMessage}
	// 3. send the inner encypted layer to the destination, to the TunnelGatewayIP

	var infoPackage shared.InfoPackage
	json.Unmarshal(message[:], &infoPackage)

	destinationNodeIP := infoPackage.GatewayInfo.TunnelGatewayIP
	eInnerMessage := infoPackage.EncryptedData

	if destinationNodeIP != ownAddress {
		conn, err := net.Dial("tcp", destinationNodeIP)
		if err == nil {
			defer conn.Close()
			conn.Write(eInnerMessage)
		} else {
			outLog.Println("TCP conn error - receiveFloodingMessages")
		}
	} else {
		receivedMessage(eInnerMessage)
	}
} // receiveFloodingMessages

func updateLocalGatewayMap(nodeID int, gatewayInfo shared.TunnelGatewayInfo, isDelete bool) {
	// update the local gatewayMap
	gatewayMap.Lock()
	defer gatewayMap.Unlock()
	if isDelete {
		delete(gatewayMap.allGateways, nodeID)
	} else {
		gatewayMap.allGateways[nodeID] = gatewayInfo
	}
}

func updateTunnelMap(tunnelID int, tunnelInfo shared.TunnelInfo, isDelete bool) {
	// update the local tunnelMap
	tunnelMap.Lock()
	defer tunnelMap.Unlock()
	if isDelete {
		delete(tunnelMap.allTunnels, tunnelID)
	} else {
		if _, ok := tunnelMap.allTunnels[tunnelID]; ok {
			if tunnelInfo.TunnelRole == shared.ENDPOINT ||
				(tunnelInfo.TunnelRole == shared.PARTICIPANT && tunnelMap.allTunnels[tunnelID].TunnelRole != shared.ENDPOINT) {
				tunnelMap.allTunnels[tunnelID] = tunnelInfo
			}
		} else {
			tunnelMap.allTunnels[tunnelID] = tunnelInfo
		}
	}
} // updateTunnelMap

// Setup TCP Listener for messages
func setupTCPListener() (tcpListener net.Listener) {
	addrs, _ := net.InterfaceAddrs()
	ln, _ := net.Listen("tcp", ":0")

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ownAddress = ipnet.IP.String() + ":" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
				break
			}
		}
	}

	go listenToConnection(ln)

	return ln
} //setupTCPListener

func generateRSAPrivateKey() (privKey *rsa.PrivateKey, err error) {
	reader := rand.Reader
	privKey, err = rsa.GenerateKey(reader, 2048)
	if err != nil {
		return nil, err
	}
	return privKey, err
} //generateRSAPrivateKey

func generateAESKey() (privKey *[32]byte, err error) {
	key := [32]byte{}
	_, err = io.ReadFull(rand.Reader, key[:])
	if err != nil {
		return nil, err
	}
	return &key, nil
} //generateAESKey

func setUpNode(serverIpPort string) (err error) {
	ownRouterPrivKey, err = generateRSAPrivateKey()
	var heartBeatInterval int
	c, err := rpc.Dial("tcp", serverIpPort)
	serverRPC = c
	if err != nil {
		return err
	}

	err = c.Call("RServer.Register", shared.RegisterNode{NodeIp: ownAddress, RouterPubKey: &ownRouterPrivKey.PublicKey}, &heartBeatInterval)

	if err != nil {
		return err
	}

	var _ignored bool
	err = c.Call("RServer.GenerateNodeID", &_ignored, &ownID)

	if err != nil {
		return err
	}

	go runHeartBeat(serverIpPort, &ownRouterPrivKey.PublicKey, heartBeatInterval)
	return nil
} //setUpNode

func runHeartBeat(ipPort string, pubKey *rsa.PublicKey, heartbeat int) {
	var _ignored bool
	defer serverRPC.Close()
	for {
		serverRPC.Call("RServer.Heartbeat", pubKey, &_ignored)
		time.Sleep(time.Duration(heartbeat/2) * time.Millisecond)
	}
} //runHeartBeat

func initializeGatewayMap() {
	var _ignored bool
	nodes := make(map[string]string)
	serverRPC.Call("RServer.GetAllNodes", &_ignored, &nodes)
	keys := make([]string, 0)
	for k := range nodes {
		keys = append(keys, k)
	}
	if len(keys) > 0 {
		jsonMsg, _ := json.Marshal(shared.Package{TunnelID: shared.REQUEST_GATEWAY_MAP, EncryptedData: []byte(ownAddress)})
		requestAddress := ""
		if ownAddress != nodes[keys[0]] {
			requestAddress = nodes[keys[0]]
		} else if ownAddress == nodes[keys[0]] && len(keys) > 1 {
			requestAddress = nodes[keys[1]]
		}
		if requestAddress != "" {
			conn, err := net.Dial("tcp", requestAddress)
			if err == nil {
				defer conn.Close()
				conn.Write(jsonMsg)
			}
		}
	}
} //initializeGatewayMap

func sendGatewayMap(requesterAddress string) {
	gatewayMap.Lock()
	msg, _ := json.Marshal(gatewayMap.allGateways)
	gatewayMap.Unlock()
	jsonMsg, _ := json.Marshal(shared.Package{TunnelID: shared.SEND_GATEWAY_MAP, EncryptedData: msg})
	conn, err := net.Dial("tcp", requesterAddress)
	if err == nil {
		defer conn.Close()
		conn.Write(jsonMsg)
	}
} //sendGatewayMap

// ****************************** Functions for Encryption/Decryption ******************************

func encrypt(message []byte, pseudoPubKey *rsa.PublicKey) ([]byte, error) {
	encryptedMessage, err := rsa.EncryptPKCS1v15(rand.Reader, pseudoPubKey, message)
	if err != nil {
		return nil, err
	}

	return encryptedMessage, nil
} // encrypt

func decrypt(message []byte, pseudoPrivKey *rsa.PrivateKey) ([]byte, error) {
	decryptedMessage, err := rsa.DecryptPKCS1v15(rand.Reader, pseudoPrivKey, message)
	if err != nil {
		return nil, err
	}

	return decryptedMessage, nil
} // decrypt

func encryptAES(plaintext []byte, key *[32]byte) (ciphertext []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
} // encryptAES

func decryptAES(ciphertext []byte, key *[32]byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("Error: malformed ciphertext")
	}

	return gcm.Open(nil,
		ciphertext[:gcm.NonceSize()],
		ciphertext[gcm.NonceSize():],
		nil,
	)
} // decryptAES

// ****************************** Functions for Conversions ******************************

func publicKeyToString(pubkey *rsa.PublicKey) string {
	publicKeyBytes, _ := x509.MarshalPKIXPublicKey(pubkey)
	return hex.EncodeToString(publicKeyBytes)
} //publicKeyToString

func publicKeyStringToKey(pubkeystring string) (rsaPub *rsa.PublicKey, err error) {
	publicKeyBytesRestored, _ := hex.DecodeString(pubkeystring)
	pubKey, err := x509.ParsePKIXPublicKey(publicKeyBytesRestored)
	rsaPub, _ = pubKey.(*rsa.PublicKey)
	return rsaPub, err
} //publicKeyStringToKey

func convertStructToString(val interface{}) string {
	retVal, _ := json.Marshal(val)
	return string(retVal)
} //convertStructToString

func convertStringToByte(val string) []byte {
	return []byte(val)
} //convertStringToByte

func convertByteToString(val []byte) string {
	return string(val[:])
} //convertByteToString

func checkError(err error) {
	if err != nil {
		outLog.Println("Error is: ", err.Error())
	}
} //checkError

// ******************************  LOGGER ******************************

func shivizSend(listen, send, send_text, receive_text string, msg []byte) {
	conn := setupConnection(send, listen)
	if conn == nil {
		return
	}
	outgoingMessage := 0
	outBuf := Logger.PrepareSend(send_text, outgoingMessage)
	_, errWrite := conn.Write(outBuf)
	// checkError(errWrite)
	if errWrite != nil {
		return
	}

	var inBuf [512]byte
	var incommingMessage int
	n, errRead := conn.Read(inBuf[0:])
	if errRead != nil {
		return
	}
	// checkError(errRead)
	Logger.UnpackReceive(receive_text, inBuf[0:n], &incommingMessage)
	// fmt.Println("GOT BACK : %d\n", incommingMessage)
	time.Sleep(1)
} // shivizSend

func shivReceive(listen, send_text, receive_text string) {
	conn, err := net.ListenPacket("udp", listen)
	// checkError(err)
	if err != nil {
		return
	}

	var buf [512]byte
	n := 1

	_, addr, err := conn.ReadFrom(buf[0:])
	var incommingMessage int
	Logger.UnpackReceive(receive_text, buf[0:], &incommingMessage)
	fmt.Printf("Received %d\n", incommingMessage)
	checkError(err)

	outBuf := Logger.PrepareSend(send_text, n)

	conn.WriteTo(outBuf, addr)
	conn.Close()
} // shivReceive

func setupConnection(sendingPort, listeningPort string) *net.UDPConn {
	rAddr, errR := net.ResolveUDPAddr("udp4", sendingPort)
	checkError(errR)
	lAddr, errL := net.ResolveUDPAddr("udp4", listeningPort)
	checkError(errL)

	conn, errDial := net.DialUDP("udp", lAddr, rAddr)
	checkError(errDial)
	if (errR == nil) && (errL == nil) && (errDial == nil) {
		return conn
	}
	return nil
} // setupConnection

// ******************************  MAIN ******************************

func main() {

	args := os.Args[1:]

	if len(args) != 1 {
		fmt.Println("Usage go run node.go [serverIp:Port]")
		return
	}

	serverIpPort := args[0]
	ownPseudoPrivKey, _ = generateRSAPrivateKey()
	ownPseudoPubKey := &ownPseudoPrivKey.PublicKey
	outLog.Println("Node Pseudonym public key is", publicKeyToString(ownPseudoPubKey))
	ln := setupTCPListener()
	defer ln.Close()

	addrs, _ := net.InterfaceAddrs()
	ln_rpc, _ := net.Listen("tcp", ":0")

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				address_rpc := ipnet.IP.String() + ":" + strconv.Itoa(ln_rpc.Addr().(*net.TCPAddr).Port)
				ownUDPIpPort = address_rpc
				net.ResolveTCPAddr("tcp", address_rpc)
				outLog.Printf("Node started. RPC Receiving on %v\n", address_rpc)
			}
		}
	}

	nodeRPC := new(NodeRPC)
	rpc.Register(nodeRPC)
	go rpc.Accept(ln_rpc)

	//connect to server and set heartBeat
	err := setUpNode(serverIpPort)
	if err != nil {
		return
	}

	outLog.Println("Node ID is", ownID)
	AddNode(ownID, publicKeyToString(ownPseudoPubKey))

	Logger = govec.InitGoVector("node"+strconv.Itoa(ownID), "node"+strconv.Itoa(ownID))
	message := []byte("")
	go shivizSend(ownUDPIpPort, serverIpPort, "Setting up node to server", "Completed node-server setup", message)

	initializeGatewayMap()

	time.Sleep(time.Second)
	inboundTunnelID = createInboundTunnel(tunnelLength)

	for {
		time.Sleep(10 * time.Second)
		inboundTunnelID = createInboundTunnel(tunnelLength)
	}

	return

}
