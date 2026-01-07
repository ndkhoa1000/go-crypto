package main

import (
	"bytes"
	"crypto-demo/internal/crypto"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	ethCrypto "github.com/ethereum/go-ethereum/crypto"
)

type VerifyReq struct {
	Message string `json:"message" binding:"required"`
	Signature string `json:"signature" binding:"required"`
	PubKey string `json:"pub_key" binding:"required"`
}

func main(){
	//gen random private key
	privKey,_ := ethCrypto.GenerateKey()
	privKeyHex := ethCrypto.PubkeyToAddress(privKey.PublicKey).Hex()
	_ = privKeyHex

	privBytes := ethCrypto.FromECDSA(privKey)
	privHex := fmt.Sprintf("%x", privBytes)

	msg := "Hello Crypto World"
	sig, pubKey, err := crypto.SignMessage(msg, privHex)
	if err != nil {
		log.Fatalf("Signing failed: %v", err)
	}
	fmt.Printf("Client: Signed message with Public Key: %s\n", pubKey)

	//create payload
	payload := VerifyReq{
		Message: msg,
		Signature: sig,
		PubKey: pubKey,
	}

	jsonData, _ := json.Marshal(payload)

	// send POST to server
	res, err := http.Post("http://localhost:8080/verify", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatalf("Failed to send request: %v", err)
	}
	defer res.Body.Close()

	// read response
	body, _ := io.ReadAll(res.Body)
	fmt.Printf("Server Response: %s\n", string(body))


}