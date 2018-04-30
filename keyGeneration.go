/*
 * Genarate rsa keys.
 */

package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"./shared"
)

var tunnelMap map[int]shared.TunnelInfo = make(map[int]shared.TunnelInfo)

func main() {
	makeTunnelMap()
	reader := rand.Reader
	bitSize := 2048

	priv1, err := rsa.GenerateKey(reader, bitSize)
	checkError(err)

	publicKey := priv1.PublicKey

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(priv1)
	encodedBytes := hex.EncodeToString(privateKeyBytes)
	fmt.Println("Private key:")
	fmt.Printf("%s\n", encodedBytes)

	privateKeyBytesRestored, _ := hex.DecodeString(encodedBytes)
	priv2, _ := x509.ParsePKCS1PrivateKey(privateKeyBytesRestored)

	encodedPubBytes := publicKeyToString(&publicKey)
	fmt.Println("Public key:")
	fmt.Printf("%s\n", encodedPubBytes)

	convertedPubKey, _ := publicKeyStringToKey(encodedPubBytes)

	message := []byte("message to be signed")

	hashed := sha256.Sum256(message)

	signature, err := rsa.SignPKCS1v15(reader, priv1, crypto.SHA256, hashed[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from signing: %s\n", err)
		return
	}

	err = rsa.VerifyPKCS1v15(&priv1.PublicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from verification: %s\n", err)
		return
	}

	err = rsa.VerifyPKCS1v15(&priv2.PublicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from verification: %s\n", err)
		return
	}

	// Encrypt the data
	out, err := encrypt(message, convertedPubKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from encrypt: %s\n", err)
	}

	decryptedMessage, err := decrypt(out, priv1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from decrypt: %s\n", err)
	}

	if !bytes.Equal(message, decryptedMessage) {
		fmt.Fprintf(os.Stderr, "Messages do not match, original: %s actual: %s\n", message, decryptedMessage)
	} else {
		fmt.Println("The RSA key messages match")
	}
	// fmt.Println("THE messages are: %s, %s", message, decryptedMessage)
	// fmt.Fprintf(os.Stderr, "The encrypted message: %s\n", out)

	// TESTING FOR THE AES KEY ENCRYPTION

	// for i := 0; i < 1000; i++ {

	aesKey, _ := generateAESKey()
	encryptedD, _ := encryptAES(message, aesKey)
	decryptedD, _ := decryptAES(encryptedD, aesKey)
	if !bytes.Equal(message, decryptedD) {
		fmt.Fprintf(os.Stderr, "AES Key Messages do not match, original: %s actual: %s\n", message, decryptedD)
	} else {
		fmt.Println("The AES key messages match")
	}

	// fmt.Println("The AES KEY IS: ", aesKey)
	messageToSend := shared.Message{AESKey: aesKey, PseudonymPublicKey: "", MessageString: "", NodeID: 2, NeedsReply: false}
	jsonMsg, _ := json.Marshal(messageToSend)
	encryptedMsg, _ := encrypt(jsonMsg, &priv1.PublicKey)
	decryptedMsg, _ := decrypt(encryptedMsg, priv1)
	var messageSent shared.Message
	err = json.Unmarshal(decryptedMsg, &messageSent)

	secondAESMsgE, _ := encryptAES(message, messageSent.AESKey)
	tempPkg := shared.Package{4, secondAESMsgE}
	tempPkgM, _ := json.Marshal(tempPkg)
	secondAESMsgE2, _ := encryptAES(tempPkgM, messageSent.AESKey)

	tempPkg2 := shared.Package{4, secondAESMsgE2}
	tempPkgM2, _ := json.Marshal(tempPkg2)
	secondAESMsgE3, _ := encryptAES(tempPkgM2, messageSent.AESKey)

	var secondAESMsgD3 []byte
	// tunnelMap[2] = shared.TunnelInfo{TunnelID: 5, TunnelKey: messageSent.AESKey}
	for _, v := range tunnelMap {
		fmt.Println("FRANCES THIS IS THE TUNNEL KEY", v.TunnelKey)
		secondAESMsgD, _ := decryptAES(secondAESMsgE3, v.TunnelKey)
		// secondAESMsgD, _ := decryptAES(secondAESMsgE3, messageSent.AESKey)
		var tempD1 shared.Package
		err = json.Unmarshal(secondAESMsgD, &tempD1)
		// checkError(err)
		// secondAESMsgD2, _ := decryptAES(tempD1.EncryptedData, v.TunnelKey)
		_, err := decryptAES(secondAESMsgE3, messageSent.AESKey)

		fmt.Println("FRANCES CHECK ERROR")
		checkError(err)

		// var tempD2 shared.Package
		// err = json.Unmarshal(secondAESMsgD2, &tempD2)
		// checkError(err)

		// secondAESMsgD3, err = decryptAES(tempD2.EncryptedData, v.TunnelKey)
		// if err == nil {
		// 	break
		// }
		// secondAESMsgD3, _ = decryptAES(tempD2.EncryptedData, messageSent.AESKey)
	}
	// if err != nil {
	// 	fmt.Println("DECRYPT AES HAS AN ERROR")
	// }
	if !bytes.Equal(secondAESMsgD3, message) {
		fmt.Println("The AESKeys do not match after encryption and decrytion + marshalling and unmarshalling")
	} else {
		fmt.Println("The two AESKeys do match")
	}
	// }

}

func makeTunnelMap() {
	for i := 0; i < 3; i++ {
		key, _ := generateAESKey()
		tunnelMap[i] = shared.TunnelInfo{TunnelID: i, TunnelKey: key}
	}

}

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

func encrypt(message []byte, pseudoPubKey *rsa.PublicKey) ([]byte, error) {
	encrptedMessage, err := rsa.EncryptPKCS1v15(rand.Reader, pseudoPubKey, message)
	return encrptedMessage, err
} // encrypt

func decrypt(message []byte, pseudoPrivKey *rsa.PrivateKey) ([]byte, error) {
	decryptedMessage, err := rsa.DecryptPKCS1v15(rand.Reader, pseudoPrivKey, message)
	return decryptedMessage, err
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
		fmt.Println("Error: malformed ciphertext") // TODOSULTAN make a meaningful error
		return nil, errors.New("Error: malformed ciphertext")
	}

	return gcm.Open(nil,
		ciphertext[:gcm.NonceSize()],
		ciphertext[gcm.NonceSize():],
		nil,
	)
} // decryptAES

func generateAESKey() (privKey *[32]byte, err error) {
	key := [32]byte{}
	_, err = io.ReadFull(rand.Reader, key[:])
	if err != nil {
		checkError(err)
		return nil, err
	}
	return &key, nil
} //generateAESKey

func saveGobKey(fileName string, key interface{}) {
	outFile, err := os.Create("key/" + fileName)
	checkError(err)
	defer outFile.Close()

	encoder := gob.NewEncoder(outFile)
	err = encoder.Encode(key)
	checkError(err)
}

func savePEMKey(fileName string, key *rsa.PrivateKey) {
	outFile, err := os.Create("key/" + fileName)
	checkError(err)
	defer outFile.Close()

	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	err = pem.Encode(outFile, privateKey)
	checkError(err)
}

func savePublicPEMKey(fileName string, pubkey rsa.PublicKey) {
	asn1Bytes, err := asn1.Marshal(pubkey)
	checkError(err)

	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	pemfile, err := os.Create(fileName)
	checkError(err)
	defer pemfile.Close()

	err = pem.Encode(pemfile, pemkey)
	checkError(err)
}

func checkError(err error) {
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		// os.Exit(1)
	}
}

// func setUpNode(ipPort string, serverIpPort string) {
// 	ownRouterPrivKey, err := generateRSAPrivateKey()
// 	var _ignored bool
// 	c, err := rpc.Dial("tcp", serverIpPort)
// 	addr := "127.0.0.1:" + ipPort

// 	err = c.Call("RServer.Register", shared.RegisterNode{NodeIp: addr, RouterPubKey: &ownRouterPrivKey.PublicKey}, &_ignored)
// 	checkError(err)

// 	go runHeartBeat(serverIpPort, &ownRouterPrivKey.PublicKey)

// 	var nodes map[string]string
// 	err = c.Call("RServer.GetAllNodes", &_ignored, &nodes)
// 	fmt.Println("HERE")
// 	fmt.Println(nodes)

// 	message := []byte("message to be signed")

// 	for k, _ := range nodes {
// 		fmt.Println("I WILL LOOK THROUGH THE SERVER MAP")
// 		testPubKey, _ := publicKeyStringToKey(k)
// 		out, _ := encrypt(message, testPubKey)
// 		decryptedMessage, _ := decrypt(out, ownRouterPrivKey)
// 		if !bytes.Equal(message, decryptedMessage) {
// 			fmt.Fprintf(os.Stderr, "Messages do not match, original: %s actual: %s\n", message, decryptedMessage)
// 		}
// 	}

// 	stringpub := publicKeyToString(&ownRouterPrivKey.PublicKey)
// 	fmt.Println("Let's check")
// 	fmt.Println(stringpub)
// }
