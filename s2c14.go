package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"crypto/rand"

	"github.com/kevinkenan/cryptopals/utils"
)

// This is a more general version of the solution to s2c12. This one will also
// solve that challenge.
func s2c14() {
	fmt.Println("Set 2, Challenge 14")

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

	// Randomly determine the length of the prefix.
	prefixLen := make([]byte, 1)
	_, err = rand.Read(prefixLen)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Generate a random prefix.
	prefix := make([]byte, int(prefixLen[0]))
	_, err = rand.Read(prefix)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Create an encryption oracle with the new key and mysterytext.
	o := c14oracle{key, prefix, mysterytext}
	// Uncomment the next line to solve s2c12 instead.
	// o = c14oracle{key, []byte{}, mysterytext}

	// Find the blockSize
	blockSize, err := c14findBlockSize(o)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Detect the mode
	mode, err := c14findMode(o, blockSize)
	if err != nil {
		fmt.Println(err)
		return
	}
	if mode != "ECB" {
		fmt.Println("ERROR: detected CBC mode.")
		return
	}

	// Get the output of the oracle with just the encrypted prefix and
	// mysterytext.
	ciphertext, err := o.getEncryptedData([]byte{})
	if err != nil {
		fmt.Println(err)
		return
	}

	// We need info about the unknown prefix that the oracle adds before our
	// input. prefixBlocks is the size of the prefix in blocks and
	// prefixPadding is the the number of bytes required to completly fill the
	// last block of the prefix.
	prefixPadding, prefixBlocks, err := c14getPrefixPadding(o, blockSize)
	if err != nil {
		fmt.Println(err)
		return
	}

	// blockCount is the number of blocks required to encrypt just the mysterytext.
	blockCount := (len(ciphertext)/blockSize)-prefixBlocks

	// attacktext holds the plaintext we use to attack the oracle. We always 
	// know all the bytes of attacktext except the last one, which is the
	// byte we attempting to discover.
	attacktext := make([]byte, prefixPadding+(blockCount*blockSize))

	// The attack window is the last block of the ciphertext produced by
	// encrypting the attack text. Since this block contains the encrypted
	// value of the unknown, last byte of the attacktext, it is the only block
	// we are really interested in.
	attackWindowStart := ((prefixBlocks+blockCount-1)*blockSize)
	attackWindowEnd := ((prefixBlocks+blockCount)*blockSize)

	// The probe allows us to control what bytes are in the attack window.
	// Since we know all of the bytes in probe (they're all 'A's), we can
	// isolate just one unknown byte of the mystertext in the attack window.
	// The initial length of probe is one less than the length of the
	// ciphertext. This size set us up to attack the first byte of the
	// mystertext.
	probe := bytes.Repeat([]byte("A"), (prefixPadding+blockCount*blockSize)-1)

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
		// if i < 1600 {
		// 	fmt.Println("PROBE:")
		// 	cryptopals.PrintBlocks(o.getText(probe[0:i]), blockSize)
		// 	fmt.Println("EMPTY:")
		// 	cryptopals.PrintBlocks(o.getText([]byte{}), blockSize)
		// 	fmt.Println("")
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

			// Check to see if the trialtext matches the target within the
			// attack window.
			if c14identicalBytesInWindow(trialtext, target, attackWindowStart, attackWindowEnd) {
				// We have uncovered a byte of the mysterytext: b.
				foundtext = append(foundtext, b)
				foundbyte = true
				break
			}
		}
		if !foundbyte {
			// We should never get here.
			fmt.Println("ERROR: Didn't find byte", i)
			fmt.Println(string(foundtext))
			return
		}
		// cryptopals.PrintBlocks(foundtext, blockSize)
	}

	if bytes.Equal(foundtext, mysterytext) {
		cryptopals.PrintSuccess(string(foundtext[0:15])+"...")
	} else {
		cryptopals.PrintFailure("")
	}
	fmt.Println("  Block size:", blockSize)
	fmt.Println("  Mode:", mode)

	// Uncomment to see the full discovered mysterytext
	// fmt.Println(string(foundtext))
}


func c14getPrefixPadding(o c14oracle, blockSize int) (int, int, error) {
	// Find the number of blocks used by the prefix. testText is long enough
	// to produce 2 identical encrypted blocks in the ciphertext.
	lastPrefixBlock := []byte{}
	prefixBlockCount := -1
	testtext := bytes.Repeat([]byte("A"), 3*blockSize)
	ciphertext, err := o.getEncryptedData(testtext)
	if err != nil {
		return 0, 0, err
	}
	// Find the identical blocks produced by testtext.
	pBlock := []byte{}
	for i := 0; i < len(ciphertext)/blockSize; i++ {
		block := ciphertext[i*blockSize:(i+1)*blockSize]
		if bytes.Equal(pBlock, block) {
			if i == 1 {
				// The oracle doesn't prepend a prefix.
				return 0, 0, nil
			}
			prefixBlockCount = i-1
			// lastPrefixBlock is the last block of the prefix plus any
			// necessary padding. We don't know how much padding...yet.
			lastPrefixBlock = ciphertext[(i-2)*blockSize:(i-1)*blockSize]
			break
		} else {
			pBlock = block
		}
	}

	// Find the amount of padding required so that the prefix fills its last
	// block.
	prefixPadding := 0
	for i := 0; i < blockSize; i++ {
		testtext := bytes.Repeat([]byte("A"), i)
		out, err := o.getEncryptedData(testtext)
		if err != nil {
			return 0, 0, err
		}
		// Compare the lastPrefixBlock with the encrypted data containing i
		// bytes of padding.
		if bytes.Equal(lastPrefixBlock, cryptopals.GetBlock(out, prefixBlockCount-1, blockSize)) {
			// If the blocks are the same, we've found the amount of padding
			// needed to fill the last block of the prefix.
			prefixPadding = i
			break
		}
	}

	return prefixPadding, prefixBlockCount, nil
}


func c14identicalBytesInWindow(a, b []byte, start, end int) bool {
	if bytes.Equal(a[start:end], b[start:end]) {
		return true
	} else {
		return false
	}
}


func c14findMode(o c14oracle, blockSize int) (string, error) {
	plaintext := bytes.Repeat([]byte("A"), 4*blockSize)
	ciphertext, err := o.getEncryptedData(plaintext)
	if err != nil {
		return "", err
	}
	return cryptopals.DetectAESMode(ciphertext), nil
}


func c14findBlockSize(o c14oracle) (int, error) {
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


type c14oracle struct {
	key, prefix, trailingtext []byte
}


func (o c14oracle) getEncryptedData(plaintext []byte) ([]byte, error) {
	newtext := bytes.Join([][]byte{o.prefix, plaintext, o.trailingtext}, []byte{})
	ciphertext, err := cryptopals.EncryptAESwithECB(cryptopals.Padding(newtext, 16), o.key)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}


// This function exists to give visibility into how the algorithm works. Given
// a plaintext, it returns exactly what the oracle would encrypt.
func (o c14oracle) getText(plaintext []byte) ([]byte) {
	newtext := bytes.Join([][]byte{o.prefix, plaintext, o.trailingtext}, []byte{})
	return cryptopals.Padding(newtext, 16)
}
