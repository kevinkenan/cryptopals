package main

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/kevinkenan/cryptopals/utils"
)

func s1c2() {
	fmt.Println("Set 1, Challenge 2")

	in1, _ := hex.DecodeString("1c0111001f010100061a024b53535009181c")
	in2, _ := hex.DecodeString("686974207468652062756c6c277320657965")

	// XOR in1 against in2
	out, err := cryptopals.XorByteArrays(in1, in2)
	if err != nil {
		fmt.Println("[ERROR xor_test]", err)
		return
	}

	// Check to see if the bytes of the xor match expectation
	exp, _ := hex.DecodeString("746865206b696420646f6e277420706c6179")
	if bytes.Compare(out, exp) == 0 {
		cryptopals.PrintSuccess(hex.EncodeToString(out))
	} else {
		fmt.Println("  Failure: ", hex.EncodeToString(out))
	}
}
