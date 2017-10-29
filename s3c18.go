package main

import (
	"encoding/base64"
	"fmt"

	"github.com/kevinkenan/cryptopals/utils"
)

func s3c18() {
	fmt.Println("Set 3, Challenge 18")
	var err error
	challenge := "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
	ciphertext, _ := base64.StdEncoding.DecodeString(challenge)
	nonce := make([]byte, 8)
	key := []byte("YELLOW SUBMARINE")

	plaintext, err := cryptopals.ApplyAESwithCTR(ciphertext, key, nonce, 0)
	if err != nil {
		cryptopals.PrintError(err)
		return
	}

	ps := string(plaintext)
	if ps[:8] == "Yo, VIP " {
		cryptopals.PrintSuccess(ps)
	} else {
		cryptopals.PrintFailure("")
	}
}
