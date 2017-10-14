package main

import (
	"bytes"
	"fmt"
	"math/big"
	"crypto/rand"

	"github.com/kevinkenan/cryptopals/utils"
)

func s2c11() {
	fmt.Println("Set 2, Challenge 11")

	plaintext := bytes.Repeat([]byte("A"), 64)

	// Generate a random key.
	key := make([]byte, 16)
	_, err := rand.Read(key)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Generate random bytes to prepend to the plaintext.
	preCountBig, _ := rand.Int(rand.Reader, big.NewInt(6))
	preCount := 5+preCountBig.Int64()
	preBytes := make([]byte, preCount)
	_, err = rand.Read(preBytes)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Generate random bytes to append to the plaintext.
	postCountBig, _ := rand.Int(rand.Reader, big.NewInt(6))
	postCount := 5+postCountBig.Int64()
	postBytes := make([]byte, postCount)
	_, err = rand.Read(postBytes)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Create the modified plaintext.
	modtext := append(preBytes, plaintext...)
	modtext = append(modtext, postBytes...)

	// Randomly select the mode
	var mode string
	modeSelector := make([]byte, 1)
	rand.Read(modeSelector)
	if (modeSelector[0] & byte(1)) == 0 {
		mode = "ECB"
	} else {
		mode = "CBC"
	}

	// Encrypt with the selected mode
	var ciphertext []byte
	if mode == "ECB" {
		ciphertext, err = cryptopals.EncryptAESwithECB(cryptopals.Padding(modtext, 16), key)
		if err != nil {
			fmt.Println(err)
			return
		}
	} else {
		// CBC mode requires an IV.
		iv := make([]byte, 16)
		_, err = rand.Read(iv)
		if err != nil {
			fmt.Println(err)
			return
		}
		ciphertext, err = cryptopals.EncryptAESwithCBC(cryptopals.Padding(modtext, 16), iv, key)
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	// Detect the mode.
	detectedMode := cryptopals.DetectAESMode(ciphertext)

	// Print the result.
	if detectedMode == mode {
		fmt.Println("  Success")
	} else {
		fmt.Println("  Failure")
	}

    fmt.Println("  Using:", mode)
	fmt.Println("  Detected:", detectedMode)
}
