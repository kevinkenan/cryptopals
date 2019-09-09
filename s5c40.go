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

	// Create three RSA objects.
	rsa1 := newSimpleRSA(1024)
	rsa2 := newSimpleRSA(1024)
	rsa3 := newSimpleRSA(1024)

	// Get the moduli.
	m := make([]*big.Int, 3)
	_, m[0] = rsa1.getPublicKey()
	_, m[1] = rsa2.getPublicKey()
	_, m[2] = rsa3.getPublicKey()

	// Get the ciphtertexts.
	a := make([]*big.Int, 3)
	a[0] = rsa1.encrypt(msg)
	a[1] = rsa2.encrypt(msg)
	a[2] = rsa3.encrypt(msg)

	// Crack the message using the Chinese remainder theorem.
	r, _ := crt(a, m)

	if string(rootBS(big.NewInt(3), r).Bytes()) == msg {
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

	// Compute the solution.
	r := big.NewInt(0)
	for i := range a {
		t := mul(mul(a[i], mp[i]), invmod(mp[i], m[i]))
		r.Add(r, t)
	}
	r.Mod(r, mt)

	return r, mt
}

// Simple binary search to find roots. It returns the largest integer a such
// that a^N ≤ A.
func rootBS(N, A *big.Int) (m *big.Int) {
	one := big.NewInt(1)
	two := big.NewInt(2)

	L, R, a, m := new(big.Int), new(big.Int), new(big.Int), new(big.Int)
	R.Sub(A, one)

BS:
	m.Quo(add(L, R), two)
	if L.Cmp(R) > 0 {
		return
	}
	a.Exp(m, N, nil)

	switch a.Cmp(A) {
	case -1:
		L.Add(m, one)
		goto BS
	case 1:
		R.Sub(m, one)
		goto BS
	}

	return
}
