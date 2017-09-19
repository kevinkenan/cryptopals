package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/kevinkenan/cryptopals/utils"
)

func s1c4() {
	fmt.Println("Set 1, Challenge 4")

	keys := cryptopals.GetPrintableASCIIBytes()

	lineNum := 0
	plaintext := ""
	bestScore := 100.0
	key := ""
	ciphertextLineNum := 0
	actualCiphertext := ""

	f, err := os.Open("s1c4data.txt")
	if err != nil {
		fmt.Printf("Error:", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineNum++
		ciphertext, _ := hex.DecodeString(scanner.Text())
		ciphertextLen := len(ciphertext)

		for _, k := range keys {
			// Create the test key which, in this case, is an element from keys repeated for the
			// length of the ciphertext.
			testKey := make([]byte, ciphertextLen)
			for i := 0; i < ciphertextLen; i++ {
				testKey[i] = k
			}

			// Decrypt the ciphertext by XORing it against the testKey
			trialText, err := cryptopals.XorByteArrays(ciphertext, testKey)
			if err != nil {
				fmt.Println("Error:", err)
			}

			// Score the resulting plaintext on how much it looks like english.
			score := cryptopals.ScoreText(trialText)

			// Low scores indicate that the decrypted text looks more like english.
			if score < bestScore {
				bestScore = score
				plaintext = strings.TrimSpace(string(trialText))
				key = string(k)
				ciphertextLineNum = lineNum
				actualCiphertext = scanner.Text()
			}
		}
	}

	// Check to see if we have the expected plaintext
	if plaintext == "Now that the party is jumping" {
		fmt.Println("  Success")
	} else {
		fmt.Println("  Failure")
	}

	fmt.Println("  Score:", bestScore)
	fmt.Println("  Key:", key)
	fmt.Println("  Ciphertext line number:", ciphertextLineNum)
	fmt.Println("  Ciphertext:", actualCiphertext)
	fmt.Println("  Plaintext:", plaintext)
}
