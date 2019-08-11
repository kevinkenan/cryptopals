package main

import (
	"fmt"
	"math/rand"
	"time"

	cryptopals "github.com/kevinkenan/cryptopals/utils"
)

func s3c22() {
	fmt.Println("Set 3, Challenge 22")

	// I'm simulating the passage of time rather than waiting because I'm impatient :)
	rand.Seed(time.Now().UnixNano())
	t := uint32(time.Now().Unix())
	seed := t - uint32(rand.Intn(1000))
	rnd := make(chan uint32)
	go cryptopals.RandomGen(seed, rnd)
	r := <-rnd

	now := uint32(time.Now().Unix())
	equal := false
	var recoveredSeed uint32
	var k uint32
	for k = 0; k < 1000; k++ {
		trial := make(chan uint32)
		trialSeed := now - uint32(k)
		go cryptopals.RandomGen(trialSeed, trial)
		guess := <-trial

		if guess == r {
			recoveredSeed = trialSeed
			equal = true
			break
		}
	}

	if equal {
		cryptopals.PrintSuccess("")
		fmt.Println("  Found seed", recoveredSeed, "after", k, "trials.")
	} else {
		cryptopals.PrintFailure("")
	}
}
