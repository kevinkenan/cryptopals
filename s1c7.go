package main

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
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

	// Create the cipher with the key.
	cipher, _ := aes.NewCipher([]byte("YELLOW SUBMARINE"))

	// Decrypt each block of the ciphertext.
	blockCount := len(ciphertext) / aes.BlockSize
	cleartext := make([]byte, len(ciphertext))
	for i := 0; i < blockCount; i++ {
		blockStart := i * aes.BlockSize
		blockEnd := (i + 1) * aes.BlockSize
		cipher.Decrypt(cleartext[blockStart:blockEnd], ciphertext[blockStart:blockEnd])
	}

	// Print the result
	exp := "I'm back and I'm"
	if string(cleartext[:16]) == exp {
		fmt.Println("  Success")
	} else {
		fmt.Println("  Failure")
	}
	fmt.Printf("  Decrypted %d blocks\n", blockCount)
	fmt.Printf("  Cleartext: %v...\n", string(cleartext[:16]))

	// Uncomment the next line if you want to see the entire plaintext by Vanilla Ice
	// fmt.Println(string(cleartext))
}
