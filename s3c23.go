package main

import (
	"fmt"
	"time"

	cryptopals "github.com/kevinkenan/cryptopals/utils"
)

func s3c23() {
	fmt.Println("Set 3, Challenge 23")

	ch := make(chan uint32)

	seed := uint32(time.Now().Unix())
	go cryptopals.RandomGen(seed, ch)

	var state [624]uint32
	for i, _ := range state {
		// We are assuming that the PRNG is at the beginning of a new state and so
		// will return the first element of the state. If this wasn't the case we'd
		// have to gather 624*2+1 elements and then figure out where the new state
		// began.
		y := <-ch

		y = untemperR(y, cryptopals.MT_l)
		y = untemperL(y, cryptopals.MT_t, cryptopals.MT_c)
		y = untemperL(y, cryptopals.MT_s, cryptopals.MT_b)
		y = untemperR(y, cryptopals.MT_u) // We ignore the AND here because the operand is 0xFFFFFFFF.

		state[i] = y
	}

	hackch := make(chan uint32)
	go cryptopals.HackedRandomGen(state[:], hackch)
	equal := true

	for i := 0; i < 624*3; i++ {
		if <-ch != <-hackch {
			equal = false
			break
		}
	}

	if equal {
		cryptopals.PrintSuccess("")
		fmt.Println("  Verified 1872 random numbers match between the original and hacked generators.")
	} else {
		cryptopals.PrintFailure("")
	}
}

func untemperR(n, shift uint32) uint32 {
	v := uint32(0)

	for i := uint32(0); i*shift < 32; i++ {
		v = n ^ (v >> shift)
	}

	return v
}

func untemperL(n, shift, c uint32) uint32 {
	mask := ^(uint32(0xFFFFFFFF) >> shift)
	v := n & mask

	for i := uint32(0); i*shift < 32; i++ {
		v = n ^ ((v << shift) & c)
	}

	return v
}
