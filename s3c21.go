package main

import (
	"fmt"

	cryptopals "github.com/kevinkenan/cryptopals/utils"
)

func s3c21() {
	fmt.Println("Set 3, Challenge 21")

	seed := uint32(1)
	rnd := make(chan uint32)
	go cryptopals.RandomGen(seed, rnd)

	// Using values from https://github.com/cslarsen/mersenne-twister/blob/master/test-mt.cpp
	// to validate the implementation. i is the number of iterations through
	// the generator.
	expected := []uint32{
		1791095845, // i = 0
		4282876139, // i = 1
		4005303368, // i = 3
		4290846341, // i = 7
		2876537340, // i = 15
		3925436996, // i = 31
		2884732358, // i = 63
		2321861504, // i = 127
		1195370327, // i = 255
		899765072,  // i = 511
		1714350790, // i = 1023
	}

	// Compute the values for each iteration.
	d := uint(0)
	rvalues := make([]uint32, 11)
	for i := 0; i < 1024; i++ {
		// Read the random number from the channel.
		r := <-rnd
		if uint(i) == (1<<d - 1) {
			// Store the value when we're at one of the iterations specified
			// by the test values.
			rvalues[d] = r
			d++
		}
	}

	// Compare the two slices.
	equal := true
	for i := range rvalues {
		if rvalues[i] != expected[i] {
			equal = false
			break
		}
	}

	if equal {
		cryptopals.PrintSuccess("Validated 11 values each requiring twice as many iterations as the previous value.")
	} else {
		cryptopals.PrintFailure("")
	}

	// Uncomment to see the values.
	// for i := range rvalues {
	//  fmt.Printf("%v : %v\n", rvalues[i], expected[i])
	// }
}
