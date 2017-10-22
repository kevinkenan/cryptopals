package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"sort"

	"github.com/kevinkenan/cryptopals/utils"
)

func s1c6() {
	fmt.Println("Set 1, Challenge 6")

	// Test the HammingDistance function
	s1 := "this is a test"
	s2 := "wokka wokka!!!"
	htest, err := cryptopals.HammingDistance([]byte(s1), []byte(s2))
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	if htest != 37 {
		fmt.Println("  failure: Hamming Distance test is not 37.")
		return
	}

	// Read in test data
	fileContent, err := ioutil.ReadFile("s1c6data.txt")
	if err != nil {
		fmt.Println(err)
	}

	// Decode the base64 encoding.
	ciphertext, err := base64.StdEncoding.DecodeString(string(fileContent))
	if err != nil {
		fmt.Println(err)
	}

	// Find likely key lengths no longer than 40
	scores, err := cryptopals.KeyLengthSearchRepeatedKeyXOR(ciphertext, 40)
	if err != nil {
		fmt.Println(err)
	}

	keyChars := cryptopals.GetPrintableASCIIBytes()

	keysTested := 0

	// Use the 3 most likely key lengths to find the key. The keyCandidates
	// variable will hold the 3 keys that produce the most english-like
	// output. This loop builds the keys one character at a time, starting
	// with the first key and working through to the third key.
	keyCandidates := [3][]byte{}
	for i := 0; i < len(keyCandidates); i++ {
		keyLen := scores[i].KeyLength
		trialKey := make([]byte, keyLen)
		keyCandidates[i] = trialKey

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
			bestScore := 100.0
			for _, c := range keyChars {
				keysTested++

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
					keyCandidates[i][kp] = c
					bestScore = score
				}
			}
		}
	}

	// Decrypt the full original ciphertext and score the resulting plaintext
	// using the best key generated for each of the likely key candidates.
	finalScores := make(cryptopals.ScoredTextList, len(keyCandidates))
	for i, k := range keyCandidates {
		p, _ := cryptopals.RepeatedKeyXor(ciphertext, k)
		finalScores[i] = cryptopals.ScoredText{string(p), cryptopals.ScoreText(p), string(k)}
	}

	// The most likely key is the one that produced the smallest score.
	sort.Sort(finalScores)
	bestKey := finalScores[0].Key

	// Print the result
	exp := "Terminator X: Bring the noise"
	if bestKey == exp {
		cryptopals.PrintSuccess("")
	} else {
		cryptopals.PrintFailure("")
	}
	fmt.Printf("  Key: '%v'\n", finalScores[0].Key)
	fmt.Println("  Keys tested:", keysTested)
	// Uncomment the next line if you want to see the plaintext by Vanilla Ice
	// fmt.Println(finalScores[0].Text)
}
