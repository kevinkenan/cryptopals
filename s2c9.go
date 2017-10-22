package main

import (
	"encoding/hex"
	"fmt"

	"github.com/kevinkenan/cryptopals/utils"
)

func s2c9() {
	fmt.Println("Set 2, Challenge 9")

	test := cryptopals.Padding([]byte("YELLOW SUBMARINE"), 20)

	// Print the result
	exp := "59454c4c4f57205355424d4152494e4504040404"
	if hex.EncodeToString(test) == exp {
		cryptopals.PrintSuccess(hex.EncodeToString(test))
	} else {
		cryptopals.PrintFailure("")
	}
}
