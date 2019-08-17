package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"time"

	cryptopals "github.com/kevinkenan/cryptopals/utils"
)

func s3c24() {
	fmt.Println("Set 3, Challenge 24")

	rand.Seed(time.Now().UnixNano())

	// Generate randomized message
	ascii := cryptopals.GetPrintableASCIIBytes()
	message := make([]byte, rand.Intn(100))

	for i := range message {
		message[i] = ascii[rand.Intn(len(ascii))]
	}

	known := []byte("this is a test")
	message = append(message, known...)

	// Generate a random 16 bit seed
	seed := rand.Uint32() >> 16

	// Create keystream
	keych := make(chan byte)
	reseed := make(chan uint32)
	cryptopals.MTStreamCipher(seed, reseed, keych)

	// Encrypt the message
	ciphertext := applyStreamCipherByte(keych, message)

	// Validate that reseeding and decryption work correctly
	reseed <- seed
	plaintext := applyStreamCipherByte(keych, ciphertext)

	if string(plaintext[len(message)-len(known):]) != string(known) {
		cryptopals.PrintFailure("ERROR: decrypted string didn't match the original message.")
	}

	// Brute force seed discovery assuming the plaintext is known.
	bfequal := false
	var foundkey uint16
	var trialtext []byte
	for i := uint16(0); i < uint16(0xFFFF); i++ {
		reseed <- uint32(i)
		trialtext = applyStreamCipherByte(keych, ciphertext)

		if string(trialtext[len(message)-len(known):]) == string(known) {
			bfequal = true
			foundkey = i
			break
		}
	}

	// I'm interpreting this part of the challenge as a call to write a function
	// to search through the first max_n number of bytes from an MT PRNG to see if
	// it contains a given sequence. We assume that the MT PRNG was seeded with
	// the time in the past max_t units, so we will search through many possible
	// seeds.
	max_n := 1000 // Number of bytes to search
	max_t := 25   // How far back in time to search.

	// Generate a random token.
	token := make([]byte, 16)

	// Simulate previous use of the PRNG.
	now := uint32(time.Now().Unix())
	reseed <- now - uint32(rand.Intn(max_t))
	d := rand.Intn(max_n - len(token) + 1)
	for i := 0; i < d; i++ {
		<-keych
	}

	// Fill the token array.
	for i := 0; i < len(token); i++ {
		token[i] = <-keych
	}

	// See if we can find the token in a keystream.
	tkequal := findToken(now, max_n, max_t, token)

	// Were we successful?
	if bfequal && tkequal {
		cryptopals.PrintSuccess("")
	} else {
		cryptopals.PrintFailure("")
	}

	if bfequal {
		fmt.Printf("  Found known text '%s' with key 0x%04x\n", string(trialtext[len(message)-len(known):]), foundkey)
	} else {
		fmt.Println("  Did not find the known text.")
	}

	if tkequal {
		fmt.Printf("  Found token 0x%x\n", token)
	} else {
		fmt.Println("  Did not find the token.")
	}
}

func applyStreamCipherByte(keych chan byte, in []byte) (out []byte) {
	out = make([]byte, len(in))
	for i, v := range in {
		out[i] = v ^ <-keych
	}

	return
}

func findToken(start uint32, max_n, max_t int, token []byte) (found bool) {
	// Create a new keystream
	keych := make(chan byte)
	reseed := make(chan uint32)
	cryptopals.MTStreamCipher(start, reseed, keych)

	// Search for the token
	trialseed := start
	keystream := make([]byte, max_n)

	for t := 0; t < max_t; t++ {
		reseed <- trialseed

		// Fill the keystream with bytes using the current trialseed.
		for n := 0; n < len(keystream); n++ {
			keystream[n] = <-keych
		}

		// Does the keystream contain the token?
		if bytes.Contains(keystream, token) {
			//println(" at: ", bytes.Index(keystream, token))
			return true
		}

		trialseed = trialseed - 1
	}

	return false
}
