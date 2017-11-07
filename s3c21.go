package main

import (
	"errors"
	"fmt"

	"github.com/kevinkenan/cryptopals/utils"
)

func s3c21() {
	fmt.Println("Set 3, Challenge 21")

	seed := uint32(1)
	rnd := make(chan uint32)
	go randomGen(seed, rnd)

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

func randomGen(seed uint32, ch chan uint32) {
	// Values needed by the algorithm.
	u := uint32(11)
	d := uint32(0xFFFFFFFF)
	s := uint32(7)
	b := uint32(0x9D2C5680)
	t := uint32(15)
	c := uint32(0xEFC60000)
	l := uint32(18)

	// Initialization
	var mt mt19937
	mt.init(seed)

	for {
		_, err := mt.twist()
		if err != nil {
			fmt.Println("ERROR:", err)
			return
		}

		y := mt.getNextStateValue()
		y = y ^ ((y >> u) & d)
		y = y ^ ((y << s) & b)
		y = y ^ ((y << t) & c)
		y = y ^ (y >> l)

		ch <- y
	}
}

type mt19937 struct {
	initialized bool
	n           uint32
	index       uint32
	state       []uint32
}

func (mt *mt19937) getNextStateValue() uint32 {
	v := mt.state[mt.index]
	// The twist function periodically resets mt.index back to zero so we
	// don't run into an out of range issue.
	mt.index++
	return v
}

func (mt *mt19937) init(seed uint32) {
	if mt.initialized {
		return
	}

	// Values needed by the algorithm.
	w := uint32(32)
	f := uint32(1812433253)

	// Initialize the state.
	mt.n = uint32(624)
	state := make([]uint32, mt.n)
	state[0] = seed
	for i := uint32(1); i < mt.n; i++ {
		state[i] = (f*(state[i-1]^(state[i-1]>>(w-2))) + i)
	}
	mt.state = state

	// Index points to the last element of the state.
	mt.index = mt.n

	// Mark it as initialized.
	mt.initialized = true
}

func (mt *mt19937) twist() (uint32, error) {
	if !mt.initialized {
		return 0, errors.New("Generator was not seeded")
	}

	// Values needed by the algorithm.
	m := uint32(397)
	r := uint32(31)
	a := uint32(0x9908B0DF)
	lowerMask := uint32((1 << r) - 1) // 0x7fffffff
	upperMask := uint32(^lowerMask)   // 0x80000000

	if mt.index == mt.n {
		for i := uint32(0); i < mt.n; i++ {
			x := (mt.state[i] & upperMask) + (mt.state[(i+1)%mt.n] & lowerMask)
			xA := x >> 1
			if (x % 2) != 0 { // lowest bit of x is 1
				xA = xA ^ a
			}
			mt.state[i] = mt.state[(i+m)%mt.n] ^ xA
		}
		mt.index = 0
	}

	return mt.index, nil
}
