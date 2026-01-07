package crypto

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

// SignMessage: raw msg -> hex-encode private key, return signature and public
func SignMessage(msg string, privKeyHex string)(sigHex string, pubKeyHex string, err error){
	// convert hex to priv key
	privKey, err := crypto.HexToECDSA(privKeyHex)
	if err != nil {
		return "","", err
	}

	// hash the msg
	msgData := []byte(msg)
	hash := crypto.Keccak256Hash(msgData)

	// Sign the hash
	signature, err := crypto.Sign(hash.Bytes(), privKey)
	if err != nil {
		return "","", err
	}
	// Get pubKey to return to user
	pubKeyBytes := crypto.FromECDSAPub(&privKey.PublicKey)
	return hexutil.Encode(signature),hexutil.Encode(pubKeyBytes),nil 
}

func VerifyAndGetAddress(msg string, sigHex string, pubKeyHex string) (string, error){
	// Decode
	sig, _ := hexutil.Decode(sigHex)
	pubKeyBytes, _ := hexutil.Decode(pubKeyHex)
	hash := crypto.Keccak256Hash([]byte(msg))

	// verify,
	// sigNiv contain R,S,V. Remove V (recovery ID) for simplify.
	sigNoV := sig[:len(sig)-1]

	isValid := crypto.VerifySignature(pubKeyBytes, hash.Bytes(), sigNoV)
	if !isValid {
		return "",fmt.Errorf("invalid signature")
	}

	//convert to address
	publicKey, err := crypto.UnmarshalPubkey(pubKeyBytes)
	if err != nil {
		return "", err
	}

	addr := crypto.PubkeyToAddress(*publicKey).Hex()

	return addr, nil
}