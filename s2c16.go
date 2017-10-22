package main

import (
	"fmt"
	"net/url"
	"crypto/rand"
	"strings"

	"github.com/kevinkenan/cryptopals/utils"
)

func s2c16() {
	fmt.Println("Set 2, Challenge 16")
	var err error

	// Generate a random key.
	key := make([]byte, 16)
	_, err = rand.Read(key)
	if err != nil {
		fmt.Println("ERROR:", err)
		return
	}

	// Generate a random iv.
	iv := make([]byte, 16)
	_, err = rand.Read(iv)
	if err != nil {
		fmt.Println("ERROR:", err)
		return
	}

	o := c16oracle{Key: key, IV: iv}

	// The input data is crafted to produce these blocks (note the URL query
	// escape characters):
	// 
	//   comment1%3Dcooki
	//   ng+MCs%3Buserdat
	//   a%3Dxxxxxxxxxxxx
	//   xxxxxxxxxxxxxxxx
	//   xxxxxxxxxxxxxxxx
	//   %3Bcomment2%3Dli
	//   ke+a+pound+of+ba
	//   con
	inputData := "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

	ciphertext, err := o.c16encryptUserData(inputData)
	if err != nil {
		fmt.Println("ERROR:", err)
		return
	}

	// cryptopals.PrintHexBlocks(ciphertext, 16)

	// The strategy is to flip bits in the fourth block of ciphertext,
	// starting at position 49, so that the fifth block becomes:
	// 
	//   x%3Badmin%3Dtrue
	//
	// Since we know that the fourth block consists only of 'x' (hex 0x78)
	// characters, we can change the ciphertext in a way to produce the
	// desired characters as follows (again, note that we use the query
	// encoded form for ';' and '='):
	ciphertext[49] = 0x78 ^ ciphertext[49] ^ 0x25 // %
	ciphertext[50] = 0x78 ^ ciphertext[50] ^ 0x33 // code for ; (pt1)
	ciphertext[51] = 0x78 ^ ciphertext[51] ^ 0x42 // code for ; (pt2)
	ciphertext[52] = 0x78 ^ ciphertext[52] ^ 0x61 // a
	ciphertext[53] = 0x78 ^ ciphertext[53] ^ 0x64 // d
	ciphertext[54] = 0x78 ^ ciphertext[54] ^ 0x6d // m
	ciphertext[55] = 0x78 ^ ciphertext[55] ^ 0x69 // i
	ciphertext[56] = 0x78 ^ ciphertext[56] ^ 0x6e // n
	ciphertext[57] = 0x78 ^ ciphertext[57] ^ 0x25 // %
	ciphertext[58] = 0x78 ^ ciphertext[58] ^ 0x33 // code for = (pt1)
	ciphertext[59] = 0x78 ^ ciphertext[59] ^ 0x44 // code for = (pt2)
	ciphertext[60] = 0x78 ^ ciphertext[60] ^ 0x74 // t
	ciphertext[61] = 0x78 ^ ciphertext[61] ^ 0x72 // r
	ciphertext[62] = 0x78 ^ ciphertext[62] ^ 0x75 // u
	ciphertext[63] = 0x78 ^ ciphertext[63] ^ 0x65 // e

	// Decrypt our modified ciphertext.
	plaintext, err := cryptopals.DecryptAESwithCBC(ciphertext, iv, key)
	if err != nil {
		fmt.Println("ERROR:", err)
		return
	}

	// Check to see if the decrypted ciphtertext contains ';admin=true;'.
	isAdmin, err := o.c16checkForAdmin(ciphertext)
	if err != nil {
		fmt.Println("ERROR:", err)
		return
	}

	if isAdmin {
		s, _ := url.QueryUnescape(string(plaintext))
		cryptopals.PrintSuccess(fmt.Sprintf("%v...%v", s[:33], s[58:]))
	} else {
		cryptopals.PrintFailure("")
	}
}

type c16oracle struct {
	Key, IV []byte
}

func (o c16oracle) c16checkForAdmin(ciphertext []byte) (bool, error) {
	plaintext, err := cryptopals.DecryptAESwithCBC(ciphertext, o.IV, o.Key)
	if err != nil {
		return false, err
	}

	plainstring, _ := url.QueryUnescape(string(plaintext))
	return strings.Contains(plainstring, ";admin=true;"), nil
}

func (o c16oracle) c16encryptUserData(userData string) ([]byte, error) {

	dataString := url.QueryEscape("comment1=cooking MCs;userdata=" + userData + ";comment2=like a pound of bacon")
	data := []byte(dataString)

	ciphertext, err := cryptopals.EncryptAESwithCBC(cryptopals.Padding(data, 16), o.IV, o.Key)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}