package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/kevinkenan/cryptopals/utils"
)

func s3c20() {
	fmt.Println("Set 3, Challenge 20")
	var err error
	// var guessedKey []byte

	// Read in test data
	f, err := os.Open("s3c20data.txt")
	if err != nil {
		fmt.Printf("Error:", err)
	}
	defer f.Close()

	var plaintexts [][]byte

	// Base64 decode the file of plaintexts
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		// Load a line into the plaintext slice.
		p, err := base64.StdEncoding.DecodeString(scanner.Text())
		if err != nil {
			fmt.Println(err)
		}
		plaintexts = append(plaintexts, p)
	}

	nonce := make([]byte, 8)

	// Generate a random key.
	key := make([]byte, 16)
	_, err = rand.Read(key)
	if err != nil {
		cryptopals.PrintError(err)
		return
	}

	shortestCiphertext := 1000
	longestCiphertext := 0

	// Encrypt the plaintexts.
	ciphertexts := make([][]byte, len(plaintexts))
	for i, p := range plaintexts {
		c, err := cryptopals.ApplyAESwithCTR(p, key, nonce, 0)
		if err != nil {
			cryptopals.PrintError(err)
			return
		}
		ciphertexts[i] = c
		if len(c) < shortestCiphertext {
			shortestCiphertext = len(c)
		}
		if len(c) > longestCiphertext {
			longestCiphertext = len(c)
		}
	}

	var ciphertext []byte
	for _, c := range ciphertexts {
		ciphertext = append(ciphertext, c[:shortestCiphertext]...)
	}

	keyChars := make([]byte, 256)
	for n := 0; n < 256; n++ {
		keyChars[n] = byte(n)
	}

	trialKey := make([]byte, shortestCiphertext)

	// Find the likely value for each position of the key by breaking the
	// ciphertext into blocks that would be encrypted by the same byte of
	// the key.
	for kp := 0; kp < len(trialKey); kp++ {
		// For each key position kp, get all the ciphertext characters
		// encrypted by the byte at that position. So if kp=3, the
		// ciphertextBlock would consist of every 3rd character of the
		// ciphertext.
		ciphertextBlock, err := cryptopals.BytePart(ciphertext, kp, len(trialKey))
		if err != nil {
			fmt.Println(err)
			return
		}

		// Find the best single character key for the block. This is the
		// same core algorithm used in s1c4.go.
		// bestScore := 100.0
		bestScore := 100.0
		for _, c := range keyChars {
			// XOR the ciphertext with the trial key c.
			trialText, err := cryptopals.RepeatedKeyXor(ciphertextBlock, []byte{c})
			if err != nil {
				fmt.Println(err)
				return
			}

			// Score the resulting plaintext on how much it looks like
			// english.
			score := cryptopals.ScoreText(trialText)

			// Low scores indicate that the decrypted text looks more like
			// english.
			if score < bestScore {
				// Save the trial key c that produced the good score. This
				// is where we're building the possible keys character by
				// character.
				trialKey[kp] = c
				bestScore = score
			}
		}
	}

	// Test the trial
	cleartexts := make([][]byte, len(ciphertexts))
	for i, c := range ciphertexts {
		p, err := cryptopals.XorByteStream(c[:len(trialKey)], trialKey)
		if err != nil {
			cryptopals.PrintError(err)
			return
		}
		cleartexts[i] = p
	}

	if string(cleartexts[0][:13]) == "I'm rated \"R\"" {
		cryptopals.PrintSuccess(string(cleartexts[0][:len(trialKey)]))
	} else {
		cryptopals.PrintFailure("")
	}

	// To see the entire set of decrypted texts, uncomment the following
	// loop.
	// for c := range cleartexts {
	// 	fmt.Println("   ", string(cleartexts[c]))
	// }
}
