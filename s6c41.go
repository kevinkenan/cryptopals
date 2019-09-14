package main

import (
	"bytes"
	"errors"
	"fmt"
	cryptopals "github.com/kevinkenan/cryptopals/utils"
	"math/big"
)

// Here's the math (all mod N) for this challenge. First we multiply the
// ciphertext m^e by s^e:
//     y = s^e * m^e.
// Then we decrypt y to get r:
//     r = (s^e * m^e)^d = s^(de) * m^(de) = s * m,
// where d is the private key and also the multiplicative inverse of e modulo
// ϕ(N). Finally, we simply multiply r by x, the inverse of s,
//     z = x * r = x * s * m = m,
// to get the original message m.
func s6c41() {
	fmt.Println("Set 6, Challenge 41")

	// Set up the challenge.
	srv := c41Server{}
	c := srv.captureCiphertext()
	e, N := srv.getPublicKey()

	// s can be anything so long as s > 1 mod N. I just picked 12. x is the
	// multiplicative inverse of s modulo N.
	s := big.NewInt(12)
	x := invmod(s, N)

	// Create a new value y based on the ciphertext c.
	y := mod(mul(exp(s, e, N), c), N)

	// Decrypt y. The decrypt function responds with an error if c, the captured
	// ciphertext, is given as its input. We've constructed y so that is not
	// equal to c.
	r, err := srv.decrypt(y)
	if err != nil {
		cryptopals.PrintError(err)
		return
	}

	// Use x, the multiplicative inverse of s, to recover the original message.
	z := mod(mul(x, r), N)

	// Did we get the right message?
	if string(z.Bytes()) == "break me" {
		cryptopals.PrintSuccess("Cracked unpadded message ")
	} else {
		cryptopals.PrintFailure("")
	}

}

type c41Server struct {
	rsa *simpleRSA
	h   []byte
}

func (srv *c41Server) captureCiphertext() *big.Int {
	msg := "break me"

	if srv.rsa == nil {
		srv.rsa = newSimpleRSA(1024, 3)
	}

	c := srv.rsa.encrypt(msg)
	srv.h = sha256Sum(c.Bytes())

	return c
}

func (srv *c41Server) decrypt(c *big.Int) (*big.Int, error) {
	if bytes.Equal(sha256Sum(c.Bytes()), srv.h) {
		return nil, errors.New("already decrypted")
	}

	return srv.rsa.decryptRaw(c), nil
}

func (srv *c41Server) getPublicKey() (e, n *big.Int) {
	if srv.rsa == nil {
		srv.rsa = newSimpleRSA(1024, 3)
	}

	return srv.rsa.getPublicKey()
}
