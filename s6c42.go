package main

import (
	"fmt"
	"math/big"
)

func s6c42() {
	fmt.Println("Set 6, Challenge 42")

	t := big.NewInt(22)
	rsa := newSimpleRSA(1024, 3)

	println(mod(mul(rsa.d, rsa.e), rsa.et).String())
	println(mod(exp(t, mul(rsa.d, rsa.e), rsa.n), rsa.et).String())

}
