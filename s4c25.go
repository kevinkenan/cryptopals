package main

import (
	"encoding/base64"
	"fmt"
	cryptopals "github.com/kevinkenan/cryptopals/utils"
	"io/ioutil"
)

func s4c25() {
	fmt.Println("Set 4, Challenge 25")

	// Read in test data
	fileContent, err := ioutil.ReadFile("s4c25data.txt")
	if err != nil {
		fmt.Println(err)
	}

	// Decode the base64 encoding.
	decoded, err := base64.StdEncoding.DecodeString(string(fileContent))
	if err != nil {
		fmt.Println(err)
	}

	// Decrypt.
	key := []byte("YELLOW SUBMARINE")
	plaintext, err := cryptopals.DecryptAESwithECB(decoded, key)
	if err != nil {
		cryptopals.PrintError(err)
	}

	nonce := make([]byte, 8)

	ciphertext, err := cryptopals.ApplyAESwithCTR(plaintext, key, nonce, 0)
	if err != nil {
		cryptopals.PrintError(err)
		return
	}

	// The attack text can be anything so long as it is known and the same
	// length as the ciphertext.
	attack := make([]byte, len(ciphertext))
	for i := range attack {
		attack[i] = 'x'
	}

	// Launch the attack.
	newciphertext, err := cryptopals.EditAESwithCTR(ciphertext, key, 0, attack)
	if err != nil {
		cryptopals.PrintError(err)
	}

	// Recovery is a two step process. First step...
	temptext, err := cryptopals.XorByteArrays(ciphertext, newciphertext)
	if err != nil {
		cryptopals.PrintError(err)
	}

	// Second step.
	recovered, err := cryptopals.XorByteArrays(temptext, attack)
	if err != nil {
		cryptopals.PrintError(err)
	}

	// Check if the recovered text matches the original text.
	if string(recovered) == string(plaintext) {
		cryptopals.PrintSuccess(string(recovered[:33]) + "...")
	} else {
		cryptopals.PrintFailure("")
	}
}
