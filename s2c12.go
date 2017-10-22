package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	// "math/big"
	"crypto/rand"

	"github.com/kevinkenan/cryptopals/utils"
)

func s2c12() {
	fmt.Println("Set 2, Challenge 12")

	// Decode the mystery base64 encoded text.
	b64text := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	mysterytext, err := base64.StdEncoding.DecodeString(string(b64text))
	if err != nil {
		fmt.Println(err)
		return
	}

	// Generate a random key.
	key := make([]byte, 16)
	_, err = rand.Read(key)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Create an encryption oracle with the new key and mysterytext.
	o := oracle{key, mysterytext}

	// Find the blockSize
	blockSize, err := findBlockSize(o)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Detect the mode
	mode, err := findMode(o, blockSize)
	if err != nil {
		fmt.Println(err)
		return
	}
	if mode != "ECB" {
		fmt.Println("ERROR: detected CBC mode.")
		return
	}

	// Get the output of the oracle with just the encrypted mysterytext.
	ciphertext, err := o.getEncryptedData([]byte{})
	if err != nil {
		fmt.Println(err)
		return
	}

	// blockCount is the number of blocks required to encrypt the mysterytext.
	blockCount := len(ciphertext)/blockSize

	// attacktext holds the plaintext we use to attack the oracle. We always 
	// know all the bytes of attacktext except the last one, which is the
	// byte we attempting to discover.
	attacktext := make([]byte, blockCount*blockSize)

	// The attack window is the last block of the ciphertext produced by
	// encrypting the attack text. Since this block contains the encrypted
	// value of the unknown, last byte of the attacktext, it is the only block
	// we are really interested in.
	attackWindowStart := (blockCount-1)*blockSize
	attackWindowEnd := blockCount*blockSize

	// The probe allows us to control what bytes are in the attack window.
	// Since we know all of the bytes in probe (they're all 'A's), we can
	// isolate just one unknown byte of the mystertext in the attack window.
	// The initial length of probe is one less than the length of the
	// ciphertext. This size set us up to attack the first byte of the
	// mystertext.
	probe := bytes.Repeat([]byte("A"), blockCount*blockSize-1)

	// Prebuild a slice containing the bytes we'll use to attack the byte
	// isolated by the probe in the attack window.
	allBytes := make([]byte, 256)
	for n := 0; n < 256; n++ {
		allBytes[n] = byte(n)
	}

	// As we discover the actual bytes of the mysterytext, we'll store them in
	// foundtext.
	foundtext := make([]byte, 0, len(ciphertext))

	// Each iteration through this loop, attacks and discovers one byte of the
	// mystery text. That byte is the last byte in the attack window.
	for i := len(probe); i >= 0; i-- {
		// The target is the encrypted data with a single unknown byte of
		// mysterytext in the attack window. Each iteration through the loop
		// lessens the amount of probe data we encrypt by one byte, which
		// draws one more byte of the mysterytext into the attack window.
		target, err := o.getEncryptedData(probe[0:i])
		if err != nil {
			fmt.Println(err)
			return
		}

		// Uncomment this block of code to get better insight into what is
		// happening internally in this algorithm.
		// fmt.Printf("> %v, %v, %v\n", len(target), len(ciphertext), len(probe[0:i]))
		// if i < 16 {
		// 	fmt.Println("p", o.getText(probe[0:i]))
		// 	fmt.Println("r", o.getText([]byte{}))
		// }

		// If the length of the target is the same as the length of the
		// ciphertext with no probe, then the size of the probe slice is equal
		// to one less than the size of the padding added by the oracle when
		// there's no input---when the probe slice equals the size of the
		// padding added by the oracle when there is no input, the oracle will
		// add a full block of extra padding. So as soon as they are equal,
		// we know that we've recovered all the mysterytext.
		if len(target) == len(ciphertext) {
			break
		}

		foundbyte := false
		// This loop tries each possible byte to see which one encrypts
		// identically to the target within the attack window.
		for _, b := range allBytes {
			// We set attacktext to be probe + foundtext + b, where b is the
			// byte we are testing to see if it will produce the same
			// encrypted text as the target (within the attack window).
			copy(attacktext, probe[0:i])
			copy(attacktext[i:], foundtext)
			attacktext[len(attacktext)-1] = b

			// We have the oracle encrypt attacktext. This produces trialtext
			// which we are going to test next.
			trialtext, err := o.getEncryptedData(attacktext)
			if err != nil {
				fmt.Println(err)
				return
			}

			// Check to see if the trialtext matches the target withing the
			// attack window.
			if identicalBytesInWindow(trialtext, target, attackWindowStart, attackWindowEnd) {
				// We have uncovered a byte of the mysterytext: b.
				foundtext = append(foundtext, b)
				foundbyte = true
				break
			}
		}
		if !foundbyte {
			// We should never get here.
			fmt.Println("ERROR: Didn't find byte", i)
			return
		}
	}

	if bytes.Equal(foundtext, mysterytext) {;
		cryptopals.PrintSuccess(string(foundtext[0:15])+"...")
	} else {
		cryptopals.PrintFailure("")
	}
	fmt.Println("  Block size:", blockSize)
	fmt.Println("  Mode:", mode)

	// Uncomment to see the full discovered mysterytext
	// fmt.Println(string(foundtext))
}

func identicalBytesInWindow(a, b []byte, start, end int) bool {
	if bytes.Equal(a[start:end], b[start:end]) {
		return true
	} else {
		return false
	}
}


func findMode(o oracle, blockSize int) (string, error) {
	plaintext := bytes.Repeat([]byte("A"), 2*blockSize)
	ciphertext, err := o.getEncryptedData(plaintext)
	if err != nil {
		return "", err
	}
	return cryptopals.DetectAESMode(ciphertext), nil
}

func findBlockSize(o oracle) (int, error) {
	// Initialize blockSize with the len of the unaltered ciphertext.
	ciphertext, err := o.getEncryptedData([]byte{})
	if err != nil {
		return 0, err
	}
	blockSize := len(ciphertext)
	// Keep increasing the amount of input to encrypt to find the block size.
	for i := 1; i < 40; i++ {
		plaintext := bytes.Repeat([]byte("A"), i)
		ciphertext, err = o.getEncryptedData(plaintext)
		if err != nil {
			return 0, err
		}

		// When the length of the ciphertext changes, it means the oracle had
		// to add another block. The difference in sizes is the blockSize
		if len(ciphertext) != blockSize {
			blockSize = len(ciphertext) - blockSize
			break
		}
	}
	return blockSize, nil
}

type oracle struct {
	key []byte
	trailingtext []byte
}

func (o oracle) getEncryptedData(plaintext []byte) ([]byte, error) {
	newtext := bytes.Join([][]byte{plaintext, o.trailingtext}, []byte{})
	ciphertext, err := cryptopals.EncryptAESwithECB(cryptopals.Padding(newtext, 16), o.key)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// This function exists to give visibility into how the algorithm works. Given
// a plaintext, it returns exactly what the oracle would encrypt.
func (o oracle) getText(plaintext []byte) ([]byte) {
	newtext := bytes.Join([][]byte{plaintext, o.trailingtext}, []byte{})
	return cryptopals.Padding(newtext, 16)
}
