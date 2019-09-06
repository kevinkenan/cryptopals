package main

import (
	"crypto/rand"
	"fmt"
	cryptopals "github.com/kevinkenan/cryptopals/utils"
	"math/big"
)

func s5c37() {
	fmt.Println("Set 5, Challenge 37")
	I := "username"
	P := []byte("password")

	srp := srpData{}
	srp.g = big.NewInt(2)
	srp.k = big.NewInt(3)
	srp.users = map[string][]byte{I: P}

	// Generate a big prime.
	prime, err := rand.Prime(rand.Reader, 2048)
	if err != nil {
		cryptopals.PrintError(err)
		return
	}
	srp.N = prime

	// Open a channel to a simulated server.
	ch := make(chan srpMsg)
	go srpServer(&srp, ch)

	// Is the attack successful when we login with the wrong password?
	success := srpAttackLogin(I, []byte("xxx"), srp, ch)
	if success {
		cryptopals.PrintSuccess("Attack logged in with the wrong password")
	} else {
		cryptopals.PrintFailure("Attack failed")
	}
}

func srpAttackLogin(I string, P []byte, srp srpData, ch chan srpMsg) bool {
	var s, K []byte
	var A *big.Int

	// Due to the nature of the attack, we don't actually need password P or the
	// srp data struct, but I wanted to keep the login function signature similar
	// to the one used in challenge 36. So here we just assign them to nothing
	// to keep the Go tools from throwing warnings.
	_ = P
	_ = srp

	// The attack sends 0 as the public key.
	A = big.NewInt(0)

	// Send client hello.
	ch <- srpMsg{n: A, msg: []byte(I), t: srpClientHello}

	// Receive server hello.
	if msg := <-ch; !msg.ok || msg.t != srpServerHello {
		cryptopals.PrintError(msg.err)
		return false
	} else {
		s = msg.msg
	}

	// Because the public key sent by the client is 0, the session key will also
	// be 0. Life is grand.
	K = sha256Sum(big.NewInt(0).Bytes())

	// Calculate the auth token
	tkn := sha256Sum(append(K, s...))

	// Send client validate message.
	ch <- srpMsg{t: srpClientValidate, msg: tkn}

	// Receive server validate message.
	if msg := <-ch; msg.ok && msg.t == srpServerValidate {
		return true
	} else {
		cryptopals.PrintError(msg.err)
		return false
	}
}
