package main

import (
	"encoding/hex"
	"fmt"

	"github.com/kevinkenan/cryptopals/utils"
)

func s1c5() {
	fmt.Println("Set 1, Challenge 5")

	key := "ICE"
	plaintext := `Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`

	// Encrypt the plaintext with the key.
	ciphertext, err := cryptopals.RepeatedKeyXor([]byte(plaintext), []byte(key))
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Check to see if we have the expected ciphertext.
	exp := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	if hex.EncodeToString(ciphertext) == exp {
		fmt.Println("  Success")
	} else {
		fmt.Println("  Failure")
	}

	ciphertextString := hex.EncodeToString(ciphertext)
	fmt.Printf("  %v...%v\n", ciphertextString[0:20], ciphertextString[len(ciphertextString)-20:len(ciphertextString)-1])
}
