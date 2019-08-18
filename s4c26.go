package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	cryptopals "github.com/kevinkenan/cryptopals/utils"
	"net/url"
)

func s4c26() {
	fmt.Println("Set 4, Challenge 26")
	var err error

	// Generate a random key.
	key := make([]byte, 16)
	_, err = rand.Read(key)
	if err != nil {
		cryptopals.PrintError(err)
		return
	}

	// Generate a random nonce.
	nonce := make([]byte, 16)
	_, err = rand.Read(nonce)
	if err != nil {
		cryptopals.PrintError(err)
		return
	}

	// The input data is crafted to produce this stream (note the URL query
	// escape characters):
	//
	//   comment1%3Dcooking+MCs%3Buserdata%3Dxxxxxxxxxxxxxxxx%3Bcomment2%3Dlike+a+pound+of+bacon
	//
	inputData := "xxxxxxxxxxxxxxxx"
	dataString := url.QueryEscape("comment1=cooking MCs;userdata=" + inputData + ";comment2=like a pound of bacon")
	data := []byte(dataString)

	// Encrypt the plaintext.
	ciphertext, err := cryptopals.ApplyAESwithCTR(data, key, nonce, 0)
	if err != nil {
		cryptopals.PrintError(err)
	}

	// Since we know that the plaintext consists only of 'x' (hex 0x78)
	// characters from positions 36 to 51, we can change the ciphertext in a way
	// to produce the desired characters as follows (again, note that we use the
	// url query encoded form for ';' and '='). This transforms the ciphertext
	// to an encrypted version of:
	//
	//   comment1=cooking MCs;userdata=x;admin=true;comment2=like a pound of bacon
	//
	ciphertext[37] = 0x78 ^ ciphertext[37] ^ 0x25 // %
	ciphertext[38] = 0x78 ^ ciphertext[38] ^ 0x33 // code for ; (pt1)
	ciphertext[39] = 0x78 ^ ciphertext[39] ^ 0x42 // code for ; (pt2)
	ciphertext[40] = 0x78 ^ ciphertext[40] ^ 0x61 // a
	ciphertext[41] = 0x78 ^ ciphertext[41] ^ 0x64 // d
	ciphertext[42] = 0x78 ^ ciphertext[42] ^ 0x6d // m
	ciphertext[43] = 0x78 ^ ciphertext[43] ^ 0x69 // i
	ciphertext[44] = 0x78 ^ ciphertext[44] ^ 0x6e // n
	ciphertext[45] = 0x78 ^ ciphertext[45] ^ 0x25 // %
	ciphertext[46] = 0x78 ^ ciphertext[46] ^ 0x33 // code for = (pt1)
	ciphertext[47] = 0x78 ^ ciphertext[47] ^ 0x44 // code for = (pt2)
	ciphertext[48] = 0x78 ^ ciphertext[48] ^ 0x74 // t
	ciphertext[49] = 0x78 ^ ciphertext[49] ^ 0x72 // r
	ciphertext[50] = 0x78 ^ ciphertext[50] ^ 0x75 // u
	ciphertext[51] = 0x78 ^ ciphertext[51] ^ 0x65 // e

	// Decrypt our modified ciphertext.
	plaintext, err := cryptopals.ApplyAESwithCTR(ciphertext, key, nonce, 0)
	if err != nil {
		cryptopals.PrintError(err)
		return
	}

	// Decode the url encoding.
	temptext, err := url.QueryUnescape(string(plaintext))
	if err != nil {
		cryptopals.PrintError(err)
		return
	}
	plaintext = []byte(temptext)

	// Check to see if the decrypted ciphtertext contains ';admin=true;'.
	if bytes.Contains(plaintext, []byte(";admin=true")) {
		cryptopals.PrintSuccess(fmt.Sprintf("%v...", string(plaintext)[:60]))
	} else {
		cryptopals.PrintFailure("")
		cryptopals.PrintHexBlocks(plaintext, 16)
	}
}
