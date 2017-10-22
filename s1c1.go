package main

import (
	"fmt"

	"github.com/kevinkenan/cryptopals/utils"
)

func s1c1() {
	fmt.Println("Set 1, Challenge 1")

	stringData := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

	// Convert stringData to base64
	enc, err := cryptopals.HexStringToBase64(stringData)
	if err != nil {
		fmt.Println("[ERROR b64_test]", err)
		return
	}

	// Check to see if the conversion matches expectation
	exp := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	if enc == exp {
		cryptopals.PrintSuccess(exp)
	} else {
		cryptopals.PrintFailure(exp)
	}
}
