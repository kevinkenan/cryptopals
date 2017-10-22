package main

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"io/ioutil"

	"github.com/kevinkenan/cryptopals/utils"
)

func s1c7() {
	fmt.Println("Set 1, Challenge 7")

	// Read in test data
	fileContent, err := ioutil.ReadFile("s1c7data.txt")
	if err != nil {
		fmt.Println(err)
	}

	// Decode the base64 encoding.
	ciphertext, err := base64.StdEncoding.DecodeString(string(fileContent))
	if err != nil {
		fmt.Println(err)
	}

	// Ensure that the ciphertext is a multiple of the block size.
	if len(ciphertext)%aes.BlockSize != 0 {
		fmt.Println("Ciphertext is not a multiple of the block size")
		return
	}

	// Decrypt.
	key := []byte("YELLOW SUBMARINE")
	cleartext, err := cryptopals.DecryptAESwithECB(ciphertext, key)
	if err != nil {
		fmt.Println(err)
	}

	// Print the result
	exp := "I'm back and I'm"
	if string(cleartext[:16]) == exp {
		cryptopals.PrintSuccess("")
	} else {
		cryptopals.PrintFailure("")
	}
	// fmt.Printf("  Decrypted %d blocks\n", blockCount)
	fmt.Printf("  Cleartext: %v...\n", string(cleartext[:16]))

	// Uncomment the next line if you want to see the entire plaintext by Vanilla Ice
	// fmt.Println(string(cleartext))
}
