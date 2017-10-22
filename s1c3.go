package main

import (
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/kevinkenan/cryptopals/utils"
)

func s1c3() {
	fmt.Println("Set 1, Challenge 3")

	ciphertext, _ := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	keys := cryptopals.GetPrintableASCIIBytes()
	ciphertextLen := len(ciphertext)
	scores := make(cryptopals.ScoredTextList, len(keys))

	for i, k := range keys {
		// Create the test key which, in this case, is an element from keys repeated for the
		// length of the ciphertext
		testKey := make([]byte, ciphertextLen)
		for i := 0; i < ciphertextLen; i++ {
			testKey[i] = k
		}

		// Decrypt the ciphertext by XORing it against the testKey
		plaintext, err := cryptopals.XorByteArrays(ciphertext, testKey)
		if err != nil {
			fmt.Println("Error:", err)
		}

		// Score the resulting plaintext on how much it looks like english
		scores[i] = cryptopals.ScoredText{string(plaintext), cryptopals.ScoreText(plaintext), string(k)}
	}

	// Low scores indicate that the decrypted text looks more like english
	sort.Sort(scores)

	// Uncomment to see the results from all the keys
	// for _, t := range scores {
	// 	fmt.Println("testKey:", t.Key, "score:", t.Score, "plaintext:", string(t.Text))
	// }

	// Check to see if the output with lowest score is the expected plaintext
	t := scores[0]
	if string(t.Text) == "Cooking MC's like a pound of bacon" {
		cryptopals.PrintSuccess("")
	} else {
		cryptopals.PrintFailure("")
	}

	fmt.Println("  Score:", t.Score)
	fmt.Println("  Key:", t.Key)
	fmt.Println("  Plaintext:", string(t.Text))

}
