package main

import (
	"crypto/rand"
	"fmt"
	cryptopals "github.com/kevinkenan/cryptopals/utils"
	"math/big"
)

func s5c39() {
	fmt.Println("Set 5, Challenge 39")
	one := big.NewInt(1)

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

	// Compute the RSA parameters.
	n := mul(p, q)
	et := mul(sub(p, one), sub(q, one))
	e := big.NewInt(3)
	d := new(big.Int).ModInverse(e, et)

	// Go's rand.Prime algorithm tends to create numbers such that e = 3 is not
	// relatively prime to et leading to a nil d.
	if d == nil {
		goto START
	}

	plaintext := new(big.Int).SetBytes([]byte("test"))

	// Encrypt
	ciphertext := exp(plaintext, e, n)

	// Decrypt
	foundtext := exp(ciphertext, d, n)

	// Did it work?
	if string(foundtext.Bytes()) == "test" {
		cryptopals.PrintSuccess("RSA encrypted and decrypted successfully")
	} else {
		cryptopals.PrintFailure("RSA didn't work")
	}
}
