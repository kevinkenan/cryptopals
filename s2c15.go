package main

import (
	"fmt"

	"github.com/kevinkenan/cryptopals/utils"
)

func s2c15() {
	fmt.Println("Set 2, Challenge 15")

	testText1 := []byte("ICE ICE BABY\x04\x04\x04\x04")
	testText2 := []byte("ICE ICE BABY\x05\x05\x05\x05")
	testText3 := []byte("ICE ICE BABY\x01\x02\x03\x04")

	test1 := true
	text1, err := cryptopals.StripPadding(testText1, 16)
	if err != nil {
		fmt.Println("1 ERROR:", err)
		test1 = false
	}

	test2 := true
	_, err = cryptopals.StripPadding(testText2, 16)
	if err == nil {
		fmt.Println("2 OOPS: expected nil error")
		test2 = false
	}

	test3 := true
	_, err = cryptopals.StripPadding(testText3, 16)
	if err == nil {
		fmt.Println("3 OOPS: expected nil error")
		test2 = false
	}

	if test1 && test2 && test3 {
		cryptopals.PrintSuccess(string(text1))
	} else {
		cryptopals.PrintFailure("")
	}
}
