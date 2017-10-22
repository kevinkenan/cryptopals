package main

import (
	"bufio"
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/kevinkenan/cryptopals/utils"
)

func s1c8() {
	fmt.Println("Set 1, Challenge 8")

	lineNum := 0

	f, err := os.Open("s1c8data.txt")
	if err != nil {
		fmt.Printf("Error:", err)
	}
	defer f.Close()

	// Strategy is to look for duplicate blocks in the ciphertext.
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineNum++

		// Load a line into the ciphertext variable.
		ciphertext, _ := hex.DecodeString(scanner.Text())

		// We use the blockSet map as a poor man's set.
		blockSet := make(map[string]int)
		blockCount := len(ciphertext) / aes.BlockSize
		for i := 0; i < blockCount; i++ {
			block := hex.EncodeToString(ciphertext[i*aes.BlockSize : (i+1)*aes.BlockSize])
			blockSet[block] = 0
		}

		// If the length of the map is less than the number of blocks, then at
		// least one of the blocks was duplicated.
		if len(blockSet) != blockCount {
			break
		}
	}

	// Print the result
	exp := 133
	if lineNum == exp {
		cryptopals.PrintSuccess(fmt.Sprintf("ECB encrypted line: %v", lineNum))
	} else {
		cryptopals.PrintFailure("")
	}
}
