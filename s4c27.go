package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	cryptopals "github.com/kevinkenan/cryptopals/utils"
)

func s4c27() {
	fmt.Println("Set 4, Challenge 27")
	var err error

	// Generate a random key.
	key := make([]byte, 16)
	_, err = rand.Read(key)
	if err != nil {
		cryptopals.PrintError(err)
		return
	}

	// Use the key for the iv. This is bad.
	iv := make([]byte, 16)
	copy(iv, key)

	// Encrypt some arbitrary plaintext 4 blocks long.
	plaintext := []byte("aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccdddddddddddddddd")
	ciphertext, err := cryptopals.EncryptAESwithCBC(cryptopals.Padding(plaintext, 16), iv, key)
	if err != nil {
		cryptopals.PrintError(err)
		return
	}

	// Assemble `newciphertext` to reveal the key.
	var newciphertext []byte
	firstblock := cryptopals.GetBlock(ciphertext, 0, 16)
	newciphertext = firstblock
	newciphertext = append(newciphertext, make([]byte, 16)...)
	newciphertext = append(newciphertext, firstblock...)
	newciphertext = append(newciphertext, cryptopals.GetBlock(ciphertext, 3, 16)...)
	newciphertext = append(newciphertext, cryptopals.GetBlock(ciphertext, 4, 16)...)

	// Decrypt the modified ciphertext.
	foundtext, err := cryptopals.DecryptAESwithCBC(newciphertext, iv, key)
	if err != nil {
		cryptopals.PrintError(err)
		return
	}

	// Attempt to recover the key from the output of the ValidateASCII function.
	foundkey := make([]byte, len(key))
	_, err = cryptopals.ValidateASCII(foundtext)
	if e, ok := err.(*cryptopals.InvalidASCIIError); ok {
		b1 := cryptopals.GetBlock(e.Text, 0, 16)
		b2 := cryptopals.GetBlock(e.Text, 2, 16)
		foundkey, _ = cryptopals.XorByteArrays(b1, b2)
	}

	// Did we get the key?
	if bytes.Equal(key, foundkey) {
		cryptopals.PrintSuccess("Recovered the key")
	} else {
		cryptopals.PrintFailure("Failed to recover the key")
	}

}
