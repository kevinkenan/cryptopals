package main

import (
	"fmt"
	"crypto/aes"
	"encoding/base64"
	"io/ioutil"

	"github.com/kevinkenan/cryptopals/utils"
)

func s2c10() {
	fmt.Println("Set 2, Challenge 10")

	// iv is 16 bytes of 0x00
	iv := make([]byte, 16)
	key := []byte("YELLOW SUBMARINE")

	// Read in test data
	fileContent, err := ioutil.ReadFile("s2c10data.txt")
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
	cleartext, err := cryptopals.DecryptAESwithCBC(ciphertext, iv, key)
	if err != nil {
		fmt.Println(err)
	}

	// Print the result
	exp := "I'm back and I'm"
	if string(cleartext[:16]) == exp {
		cryptopals.PrintSuccess(string(cleartext[:33])+"...")
	} else {
		cryptopals.PrintFailure("")
	}

	// fmt.Printf("  Cleartext: %v...\n", string(cleartext[:16]))

	// Uncomment the next line if you want to see the entire plaintext by Vanilla Ice
	// fmt.Println(string(cleartext))
}
