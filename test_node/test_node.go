package main

import (
	"os"
	"fmt"

	"crypto/rsa"
	"time"
	"net"
	"log"
	"crypto/rand"
	"encoding/json"
	"crypto"
	"../shared"
	"flag"
	"io/ioutil"
	"encoding/hex"
	"crypto/x509"
)

// ****************************** Global Variables ******************************

var localHost = "localhost"
var tcpType = "tcp"
var port = "3000"

var ownRouterPrivKey *rsa.PrivateKey
var ownPseudoPrivKey *rsa.PrivateKey

var gatewayMap map[crypto.PublicKey]shared.TunnelGatewayInfo = make(map[crypto.PublicKey]shared.TunnelGatewayInfo)
var tunnelMap map[int]shared.TunnelInfo = make(map[int]shared.TunnelInfo)

var config Config
var outLog *log.Logger = log.New(os.Stderr, "[node] ", log.Lshortfile|log.LUTC|log.Lmicroseconds)

var outboundTunnelKey *rsa.PublicKey

// ****************************** End Global Variables ******************************



// ****************************** Structs ******************************


type Config struct {
	Port 			 string 		  `json:"port"`
	PseudoPrivKeyString	string		  `json:"pseudo-priv-key"`
	SendMessage			Message			  `json:"send-message"`
	GatewayInfo			TestTunnelGatewayInfo	`json:"gateway-info"`
}

type Message struct {
	// Hash of the very first (empty) block in the chain.
	MsgString string `json:"msg-string"`
	DestinationPseudoKey string	`json:"destination-pseudo-key"`
}

type TestTunnelGatewayInfo struct {
	TunnelID int	`json:"tunnel-id"`
	TunnelGatewayIP string	`json:"tunnel-gateway-ip"`
	TunnelPrivateKey rsa.PrivateKey	`json:"tunnel-privkey"`
	NextHopIp string	`json:"next-hop-ip"`

}

// ****************************** End Structs ******************************


func SendMessage(pseudoPubKey *rsa.PublicKey, message string) (err error) {

	//tunnelGatewayInfo := gatewayMap[pseudoPubKey]
	//inboundGatewayIP := tunnelGatewayInfo.TunnelGatewayIP

	// createOutboundTunnel()
	inboundGatewayIP := localHost + ":" + "5000"
	fmt.Println("Starting test message")

	conn, err := net.Dial("tcp", inboundGatewayIP)
	defer conn.Close()

	if err != nil {
		return err
	}
	// Need to perform series of encryptions on message before this

	// jsonMsg := convertStringToByte(message)
	// Packaging the initial message up by encrypting the message
	// ==========
	// | message|
	// ==========
	jsonMsg, _ := json.Marshal(message)
	encryptedMsg, _ := encrypt(jsonMsg, pseudoPubKey)

	// Creation of a tunnel message that will be encrypted into a package
	// ==============================
	// | tunnelGatewayInfo | message|
	// ==============================
	tunnelId := 1
	tunnelPrivKeyStr := "308204a20201000282010100cbcb05c0b45743f65674a3aec7e09f821036133999089c9eeb80b15079e497cf8a00be16cc5c7ca1b0656fae51f6583cf62f9c81faaee900f914a814c83dc18f6be46206f59648768c4bddaad1d202df0d7326cace545e214c13b9989a7b53dbd3c1e1ae798c3f47c692aecccae4dff9883950f9eca16d27f7c074d66f8e15d1491c4c999a317d7597aed07b774043e7bd7bef8f9baa05f236fb447e861c5139d76e59d63d5728d22cc14141bf210ce36766e166954d1a71599f630bf1e8022f9f7b06e194d8403ad039e96b26e86f7af6b06bbd595d0ffff5f3370a80a66786024a54f1698048c1b64851075e644f5364006f3f0819831e10530f260117dfc5020301000102820100071898a8af1ee2c4ef19bca1576060ed7c77059059ddcce653b8f573a1eaedc6523dd8609ed91195e7b8807d07699684f8e58b8393210807faa4577df1c304bc63bb5e1673f2b9af370f65368f7bca91cdbc16bbb51786f78dd899fbd0553f04468957bc658b16a0ff2f185b152d8706ff514f9a843cd2ba338c460539792f153c854de786be1859b54a36a538f4868026d1e2447f2c62c2e1535818b802975c6d47119e899fb8dad4b4492e7f33d02bd88ca254a7543cd2c74327cd3c63791ec67811ee1b9ffa6b54a722efcff7999edc00ad8ea3f0343051e2ac197d0d5e23bd4f8f472a2c011a26ab3ffa61e7ee3b5fceea1970d2d320a0425d9fd972feb902818100cf5b6b5dac148f35644de442574d15168e500c035a88b7c0fb6ca56fc93985dce6f0b730a0047ab15f1eb684d8885ae0bef87c5b32d076f8721294c7f2e9f80de6ffc032cf2e933abeabb86587dae9eced9bbcc37228eafa874d870e3d7fafb84bb186604a8b97993b935d8a993a26b9d0d61495f4d16a68074ac152b35964e702818100fb99917dd21c228cbfd6f21eb1d0b118d5327f704584b4cf2cf2c0b4880365d6064f8a3c3f826a8848e90156c59480b03c3bd05ee2f2a3224a47222251ed7de040937673d06c31e6d1c892839ce0059d8f140f4e18b18cd7e0bccc762ffbf47b6ee0fc7af875559995b2a288733c8a803797a14ba2d85e536237e1e1c456947302818000f8a9a917ac44fb780bd15cea31c73e82ce273040d5511f0b4e77fbed1262e924ffcdabe1a403bb1ef9f2daee74bd103e74c5885bd5942917c7b480b747974ce15f2354599a1b40743233bbee05fd8089a06822f63ef0d2d99d685b8db83267879b3e48e7307e364e8c232d0a08b6b3ba21b698f93b9de6fcd9c1cc1460ffd3028180779ff48516393a542182596c2eaf4304c39956ee529f5e3882ee88a14d6a10294aa6d6dafe774b9fb0cad8502171121eb904d775c602077e6e4294002d63f5cd81e69b1345adabac4b624a0739b769f417eb39bbb011fb1d49457b11568f3d16d309360261cfa7fb7629910dbf7cb17d74f12b47830dcd0b684f999e767393f10281806ab10baea18f457fc59248e3f26b5314d7980e0075f60a2ccc90d12ebf863f5e557917c19f4da8ac99690d65660c7f82b86bd29f2f812133a71be5ac60741c057a5f54525396f4319f76b3cbe9e286e805c5bfac20f1be0f6b161f3d2b67d5668cacdf0a13253e20cd5db25fdd1f5ac2b313b4d029b463364e65e7ea82950d0a"

	privateKeyBytesRestored, _ := hex.DecodeString(tunnelPrivKeyStr)
	tunnelPrivKey, _ := x509.ParsePKCS1PrivateKey(privateKeyBytesRestored)

	tunnelCPrivKeyStr := "308204a30201000282010100aa514e2a3ed6c80b4cfe931f78dec5d245bafb653305af3c9c82f1aac46f00741d866d71ed40f81eed6a0275ede538b8f0e4556ca296e141fd66b2310e3ba633c43a2d9ed925f85149825b651ba1c991b515f4344a24eaf784f01e5895c14d20e6aa4b4dba3c7b3601d88b209c0aa0a5083d6f37232c5d91d57a4f5e001dab2eabdb5d820989a9b9d83e3b28d3138a4bd21dc6b38270b84f2467189e85b41eb6e18b90d5333805eb0eb2ff4e9895faf8f67222cfc8a31281cbb9113a6c6da4f25891c7563b43f477a8510766e0dd280555b89cac456778687b2b3bb0a560144f7108180fab51e0fffecf4cca6c22a70c31e19a4d7d68832acc9a046e7f2710350203010001028201010086f35553f3e68b2b291eadc44a2979e55a8b0596f20e970317a0498c5d88f67b0ac9f0fe4c5726429b2b5c37c4ffd329f6f5751a56d9e6323b6e9bd272cca0ac73d7053ed0205dd94abd975d4dbfabcf6004bd32916d1f20709d31ee4efa92fa76ca8850563886080cfe5f7ebf254c94772af66c61da4d69b814e9be39a94870af1ae3fdf16ab99d71d31ee96ef7c8d156f8119053126417a1f18aedcae59638abdf2f8e32d2b773d27a2e949d917c186b46e167899d229b82f544b790b4ebdaee6c1bd86776c2e22bd9e4b76303cbb1a60796ebf45ccda967394444326990b7e54f821b4f46fbe1d4f17169eab981dfc96cd02a449a8c57f9ff28edc756852102818100dd098c31d9600cbbc76fdbdf5eaa6eb6bb16cf3de165f4cad2d30b499e7769f24b9ef851921d73c6f2bbd957506ec9e12ea19011708ff6e093071e1897087ebf640c2ac63030eb3ce83d6e2ecd120f626e49d28522ddcfdcf5dcb9c2a8dd70f3a8bc4be8d3ea9c874619cc7726b4588ab8d2b105e423eb6fbd3ef69d1531e2db02818100c541f7aef92e54bd2bd1b88e0ccc3835b00148e648b9679d0e869e6473faa3d1506ed8bbefd1e99fdc29a01361adfca11c6a52dc1b141ccf4c692f9bac8dab954e2c08aeca1f4029ea7e3d47a83a15a6ccce211950a3711017605b367b6fcf67a9d000287db510c341f0fbd515b14a8e320b82fa96ff0469aa65411aa6b65e2f02818025a9bdd0b4a8702302fda56a6f37fd3b77af904a8c00927088f1db07854ff5a68a8a20e7cd4ce5706de5e247c575cb426a6eaf1cb9a05e41afebd38dff163c7aa2328c8b4ea4d7407e9611133a702c5cea4bfbea21a1c80c6f7c57ceba75590cbba0b2128f2177e078ea66739b0db9d4915f9d3852c268189717867007af83670281801d8551dc0dceb13fde5ef48fcdba826f06782ac0cc0173503dec47a820f351b0f1a8a526fb2d1f199d895d3b8952d08c0c049d81f34b7f4446db3714c52e2e8f99b35d594b468203c3e440a788b5a8a7dddebb755e6c176fa10ffa969cc28ef7a4a24c63c2ec6625d2a88e07c5c752b1152c43dddcdb2d7de2d2647be897426102818076bda74456b90c5c7bce53bc6da136885d95c2d633bacce17cde9694c74e9253fe9bfc64b7608b32afef629f556185ecd5511549c81a41b0d996fe024afea5f50f0b9fc547b5ffcd70a89ea4414201f0794480a3559c16057e0c10c8e46ed8e1f4e968006c297195964850f8a985aeb5712b6b6977a948b197c866f9300d0a6d"

	tunnelCPrivKeyBytesRestored, _ := hex.DecodeString(tunnelCPrivKeyStr)
	tunnelCPrivKey, _ := x509.ParsePKCS1PrivateKey(tunnelCPrivKeyBytesRestored)

	tunnelGatewayInfo := shared.TunnelGatewayInfo{ TunnelID: 1, TunnelGatewayIP: "localhost:5000", TunnelPublicKey: &tunnelPrivKey.PublicKey }
	// TODO: Check for error if there is no inbound tunnel
	infoPackage := shared.InfoPackage{tunnelGatewayInfo, encryptedMsg}
	infoPackageMsg, _ := json.Marshal(infoPackage)
	encryptedInfoPackage, _ := encrypt(infoPackageMsg, &tunnelCPrivKey.PublicKey)

	// Append tunnelId onto the package
	// =========================================
	// | tunnelId | tunnelGatewayInfo | message|
	// =========================================
	tunnelKey := &tunnelPrivKey.PublicKey
	finalPackage := shared.Package{tunnelId, encryptedInfoPackage}
	finalPackageMsg, _ := json.Marshal(finalPackage)
	encrypt(finalPackageMsg, tunnelKey)
	encryptedFinalPackage, _ := encrypt(finalPackageMsg, tunnelKey)


	reply := make([]byte, 1024)

	conn.Write(encryptedFinalPackage)
	fmt.Println("Wrote test message")

	size, _ := conn.Read(reply)
	fmt.Println("Read test message reply")

	reply = reply[:size]
	fmt.Println(string(reply))

	//deleteOutboundTunnel

	return err
} // SendMessage

// Setup TCP Listener for messages
func setupTCPListener(tcpPort string) (tcpListener *net.TCPListener) {
	tcpAddr := localHost + ":" + tcpPort
	resolvedTCPAddr, err := net.ResolveTCPAddr(tcpType, tcpAddr)
	tcpListener, err = net.ListenTCP(tcpType, resolvedTCPAddr)

	if err != nil {
		fmt.Println("Error listening:", err.Error())
		os.Exit(1)
	}
	// Close the conn when the application closes.

	addrs, _ := net.InterfaceAddrs()
	var serverIp string

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				serverIp = ipnet.IP.String()
				outLog.Printf("Node started. Receiving on %v\n", serverIp+":"+tcpPort)
				break
			}
		}
	}

	go listenToConnection(tcpListener)

	return tcpListener
} //setupTCPListener

func listenToConnection(tcpListener *net.TCPListener) {
	// Read the incoming connection into the buffer.
	for {
		conn, err := tcpListener.Accept()
		if err != nil {
			fmt.Println("Error accepting: ", err.Error())
			os.Exit(1)
		}
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)

		if err != nil {
			fmt.Println("Error: ", err)
		} else {
			fmt.Print("Message Received: ", string(buf), "\n")
			fmt.Println("n: ", n)
			var message []byte
			var nextHopIp string
			var tunnelRole int

			for _, tunnelInfo := range tunnelMap {
				privateKey := tunnelInfo.TunnelPrivateKey
				message, err = decrypt(message, privateKey)
				if err == nil {
					nextHopIp = tunnelInfo.NextHopIp
					tunnelRole = tunnelInfo.TunnelRole
					break
				}
			}
			fmt.Println("After tunnel map")
			var packageMessage shared.Package

			err = json.Unmarshal(message[:], &packageMessage)

			if err != nil {
				checkError(err)
			} else {
				switch tunnelRole {
				case shared.GATEWAY:
					break;
				case shared.PARTICIPANT:
					forwardMessage(packageMessage.TunnelID, packageMessage.EncryptedData, nextHopIp)
					break;
				case shared.ENDPOINT:
					break;
				default:
				}
			}
			// TODO: Remove testing code // send new string back to client
			conn.Write([]byte("trent-reply" + "\n"))
		}
	}
} // ListenToConnection

func forwardMessage(tunnelID int, message []byte, destinationIp string) {
	tunnelInfo := tunnelMap[tunnelID]
	key := tunnelInfo.TunnelPrivateKey
	message, err := encrypt(message, &key.PublicKey)
	if err == nil {
		var messagePackage shared.Package
		messagePackage.TunnelID = tunnelID
		messagePackage.EncryptedData = message

		fmt.Println("Received message with tunnelID: ", tunnelID)

		//messageToSent := convertStringToByte(messagePackage)



		conn, err := net.Dial("tcp", destinationIp)
		defer conn.Close()

		if err == nil {
			//conn.Write(messageToSent)
			return
		} else {
			checkError(err)
			// TODOJastine: node failure
		}
	}

	fmt.Println("forwardMessageParticipant: Should not reach here")
} // forwardMessageParticipant

func generateRSAPrivateKey() (privKey *rsa.PrivateKey, err error) {
	reader := rand.Reader
	privKey, err = rsa.GenerateKey(reader, 2048)
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		return nil, err
	}
	return privKey, err
} //generateRSAPrivateKey


func main() {

	path := flag.String("c", "", "Path to the JSON config")
	flag.Parse()

	if *path == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	readConfigOrDie(*path)

	fmt.Println("Config port: ", config.Port)
	fmt.Println("PseudoPrivKey port: ", config.PseudoPrivKeyString)

	fmt.Println("SendMessage: ", config.SendMessage)

	tcpPort := config.Port
	//privKeyStr := args[0]

	tcpListener := setupTCPListener(tcpPort)
	defer tcpListener.Close()


	tunnelPrivKeyStr := "308204a20201000282010100cbcb05c0b45743f65674a3aec7e09f821036133999089c9eeb80b15079e497cf8a00be16cc5c7ca1b0656fae51f6583cf62f9c81faaee900f914a814c83dc18f6be46206f59648768c4bddaad1d202df0d7326cace545e214c13b9989a7b53dbd3c1e1ae798c3f47c692aecccae4dff9883950f9eca16d27f7c074d66f8e15d1491c4c999a317d7597aed07b774043e7bd7bef8f9baa05f236fb447e861c5139d76e59d63d5728d22cc14141bf210ce36766e166954d1a71599f630bf1e8022f9f7b06e194d8403ad039e96b26e86f7af6b06bbd595d0ffff5f3370a80a66786024a54f1698048c1b64851075e644f5364006f3f0819831e10530f260117dfc5020301000102820100071898a8af1ee2c4ef19bca1576060ed7c77059059ddcce653b8f573a1eaedc6523dd8609ed91195e7b8807d07699684f8e58b8393210807faa4577df1c304bc63bb5e1673f2b9af370f65368f7bca91cdbc16bbb51786f78dd899fbd0553f04468957bc658b16a0ff2f185b152d8706ff514f9a843cd2ba338c460539792f153c854de786be1859b54a36a538f4868026d1e2447f2c62c2e1535818b802975c6d47119e899fb8dad4b4492e7f33d02bd88ca254a7543cd2c74327cd3c63791ec67811ee1b9ffa6b54a722efcff7999edc00ad8ea3f0343051e2ac197d0d5e23bd4f8f472a2c011a26ab3ffa61e7ee3b5fceea1970d2d320a0425d9fd972feb902818100cf5b6b5dac148f35644de442574d15168e500c035a88b7c0fb6ca56fc93985dce6f0b730a0047ab15f1eb684d8885ae0bef87c5b32d076f8721294c7f2e9f80de6ffc032cf2e933abeabb86587dae9eced9bbcc37228eafa874d870e3d7fafb84bb186604a8b97993b935d8a993a26b9d0d61495f4d16a68074ac152b35964e702818100fb99917dd21c228cbfd6f21eb1d0b118d5327f704584b4cf2cf2c0b4880365d6064f8a3c3f826a8848e90156c59480b03c3bd05ee2f2a3224a47222251ed7de040937673d06c31e6d1c892839ce0059d8f140f4e18b18cd7e0bccc762ffbf47b6ee0fc7af875559995b2a288733c8a803797a14ba2d85e536237e1e1c456947302818000f8a9a917ac44fb780bd15cea31c73e82ce273040d5511f0b4e77fbed1262e924ffcdabe1a403bb1ef9f2daee74bd103e74c5885bd5942917c7b480b747974ce15f2354599a1b40743233bbee05fd8089a06822f63ef0d2d99d685b8db83267879b3e48e7307e364e8c232d0a08b6b3ba21b698f93b9de6fcd9c1cc1460ffd3028180779ff48516393a542182596c2eaf4304c39956ee529f5e3882ee88a14d6a10294aa6d6dafe774b9fb0cad8502171121eb904d775c602077e6e4294002d63f5cd81e69b1345adabac4b624a0739b769f417eb39bbb011fb1d49457b11568f3d16d309360261cfa7fb7629910dbf7cb17d74f12b47830dcd0b684f999e767393f10281806ab10baea18f457fc59248e3f26b5314d7980e0075f60a2ccc90d12ebf863f5e557917c19f4da8ac99690d65660c7f82b86bd29f2f812133a71be5ac60741c057a5f54525396f4319f76b3cbe9e286e805c5bfac20f1be0f6b161f3d2b67d5668cacdf0a13253e20cd5db25fdd1f5ac2b313b4d029b463364e65e7ea82950d0a"

	privateKeyBytesRestored, _ := hex.DecodeString(tunnelPrivKeyStr)
	tunnelPrivKey, _ := x509.ParsePKCS1PrivateKey(privateKeyBytesRestored)

	tunnelMap[1] = shared.TunnelInfo{ TunnelID: 1, TunnelRole: 1, NextHopIp: "localhost:5000", TunnelPrivateKey: tunnelPrivKey }

	// The next two lines of code will decode the string of the private key

	if (Message{}) != config.SendMessage {

		destPrivKey := config.SendMessage.DestinationPseudoKey
		privateKeyBytesRestored, _ := hex.DecodeString(destPrivKey)
		ownPseudoPrivKey, _ = x509.ParsePKCS1PrivateKey(privateKeyBytesRestored)
		destPubKey := ownPseudoPrivKey.PublicKey


		SendMessage(&destPubKey, config.SendMessage.MsgString)
	}


	time.Sleep(500000 * time.Second)
	return
} // main

func readConfigOrDie(path string) {
	file, err := os.Open(path)
	handleErrorFatal("config file", err)

	buffer, err := ioutil.ReadAll(file)
	handleErrorFatal("read config", err)

	err = json.Unmarshal(buffer, &config)
	handleErrorFatal("parse config", err)
}


func encrypt(message []byte, pseudoPubKey *rsa.PublicKey) ([]byte, error) {
	encrptedMessage, err := rsa.EncryptPKCS1v15(rand.Reader, pseudoPubKey, message)
	return encrptedMessage, err
} // encrypt

func decrypt(message []byte, pseudoPrivKey *rsa.PrivateKey) ([]byte, error) {
	decryptedMessage, err := rsa.DecryptPKCS1v15(rand.Reader, pseudoPrivKey, message)
	return decryptedMessage, err
} // decrypt

func handleErrorFatal(msg string, e error) {
	if e != nil {
		outLog.Fatalf("%s, err = %s\n", msg, e.Error())
	}
}

func convertStringToByte(val string) []byte {
	return []byte(val)
} //convertStringToByte

func checkError(err error) {
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
	}
} //checkError