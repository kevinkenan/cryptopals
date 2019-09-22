package main

import (
	"errors"
	"fmt"
	cryptopals "github.com/kevinkenan/cryptopals/utils"
	"math/big"
)

func s5c40() {
	fmt.Println("Set 5, Challenge 40")
	msg := "super secret message"

	// The e component of the public key. The attack needs as many broadcasts as
	// e, so this code simply uses e for the number of broadcasts to generate.
	e := 3

	// Create an RSA object for each broadcast.
	r := make([]*simpleRSA, e)
	for i := range r {
		r[i] = newSimpleRSA(1024, e)
	}

	// Get the public key moduli.
	m := make([]*big.Int, e)
	for i := range m {
		_, m[i] = r[i].getPublicKey()
	}

	// Get the ciphertexts.
	a := make([]*big.Int, e)
	for i := range a {
		a[i] = r[i].encrypt(msg)
	}

	// Crack the message using the Chinese remainder theorem.
	res, _ := crt(a, m)
	if res == nil {
		return
	}

	// Did we recover the message?
	if string(cryptopals.RootBS(big.NewInt(int64(e)), res).Bytes()) == msg {
		cryptopals.PrintSuccess("e=3 broadcast attack cracked the encrypted message")
	} else {
		cryptopals.PrintFailure("Broadcast attack failed")
	}
}

// crt is an implementation of the Chinese remainder theorem.
func crt(a, m []*big.Int) (*big.Int, *big.Int) {
	if len(a) != len(m) {
		cryptopals.PrintError(errors.New("crt: unequal number of residues and moduli "))
		return nil, nil
	}

	// Compute the product of all the moduli.
	mt := big.NewInt(1)
	for _, v := range m {
		mt.Mul(mt, v)
	}

	// Compute the moduli products so that mp[n] is the product of all moduli
	// except the nth.
	mp := make([]*big.Int, len(a))
	for i, v := range m {
		mp[i] = new(big.Int).Div(mt, v)
	}

	// Compute the solution r.
	r := big.NewInt(0)
	for i := range a {
		t := mul(mul(a[i], mp[i]), invmod(mp[i], m[i]))
		r.Add(r, t)
	}
	r.Mod(r, mt)

	return r, mt
}
