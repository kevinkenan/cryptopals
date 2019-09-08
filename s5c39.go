package main

import (
	"crypto/rand"
	"fmt"
	cryptopals "github.com/kevinkenan/cryptopals/utils"
	"math/big"
)

func s5c39() {
	fmt.Println("Set 5, Challenge 39")

START:

	// Generate a couple big primes.
	p, err := rand.Prime(rand.Reader, 2048)
	if err != nil {
		cryptopals.PrintError(err)
		return
	}

	q, err := rand.Prime(rand.Reader, 2048)
	if err != nil {
		cryptopals.PrintError(err)
		return
	}

	n := mul(p, q)
	one := big.NewInt(1)
	et := mul(sub(p, one), sub(q, one))
	e := big.NewInt(3)
	d := new(big.Int).ModInverse(e, et)

	// Go's rand.Prime algorithm tends to create numbers such that e = 3 is not
	// relatively prime to et leading to a nil d.
	if d == nil {
		goto START
	}

	plaintext := new(big.Int).SetBytes([]byte("test"))
	ciphertext := exp(plaintext, e, n)

	foundtext := exp(ciphertext, d, n)

	if string(foundtext.Bytes()) == "test" {
		cryptopals.PrintSuccess("RSA encrypted and decrypted successfully")
	} else {
		cryptopals.PrintFailure("RSA didn't work")
	}
}
