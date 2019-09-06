package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	cryptopals "github.com/kevinkenan/cryptopals/utils"
	"math/big"
)

const (
	srpClientHello int = iota
	srpServerHello
	srpClientValidate
	srpServerValidate
)

type srpMsg struct {
	t   int      // Step in the protocol
	n   *big.Int // Integers used in the protocol
	msg []byte   // Message
	ok  bool     // true if the message was processed correctly
	err error    // Populated if ok = false.
}

type srpData struct {
	N, g, k *big.Int
	users   map[string][]byte
}

func s5c36() {
	fmt.Println("Set 5, Challenge 36")
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

	// Is login with the password successful?
	success := srpLogin(I, P, srp, ch)
	if success {
		cryptopals.PrintSuccess("Accepted the password using SRP")
	} else {
		cryptopals.PrintFailure("")
	}
}

func srpLogin(I string, P []byte, srp srpData, ch chan srpMsg) bool {
	var s []byte
	var a, A, B *big.Int

	// Generate the client's private key a and public key A.
	a = genPrivateKeySRP(256)
	A = exp(srp.g, a, srp.N)

	// Send client hello.
	ch <- srpMsg{n: A, msg: []byte(I), t: srpClientHello}

	// Receive server hello.
	if msg := <-ch; !msg.ok || msg.t != srpServerHello {
		cryptopals.PrintError(msg.err)
		return false
	} else {
		s = msg.msg
		B = msg.n
	}

	// Calculate the session key K.
	u := new(big.Int).SetBytes(sha256Sum(append(A.Bytes(), B.Bytes()...)))
	x := new(big.Int).SetBytes(sha256Sum(append(s, P...)))
	S := exp(sub(B, mul(srp.k, exp(srp.g, x, srp.N))), add(a, mul(u, x)), srp.N)
	K := sha256Sum(S.Bytes())

	// Calculate the auth token
	tkn := sha256Sum(append(K, s...))

	// Send client validate
	ch <- srpMsg{t: srpClientValidate, msg: tkn}

	// Receive server validate.
	if msg := <-ch; msg.ok && msg.t == srpServerValidate {
		return true
	} else {
		cryptopals.PrintError(msg.err)
		return false
	}
}

// This function simulates the server side of our SRP implementation. It
// receives and responds to messages.
func srpServer(srp *srpData, ch chan srpMsg) {
	var err error
	var s, K []byte
	verifiers := make(map[string]*big.Int)

	// Generate the salt s.
	s = make([]byte, 16)
	_, err = rand.Read(s)
	if err != nil {
		cryptopals.PrintError(err)
		return
	}

	// Load the verifiers into a map. We could erase the srp.users map after
	// this loop since we no longer need the plaintext passwords.
	for u, p := range srp.users {
		v := new(big.Int)
		v.SetBytes(sha256Sum(append(s, p...)))
		v.Exp(srp.g, v, srp.N)
		verifiers[u] = v
	}

	state := 0
	for {
		switch m := <-ch; m.t {
		case srpClientHello:
			if state != 0 {
				m.ok = false
				m.err = errors.New("protocol error 1")
				ch <- m
				close(ch)
				return
			}
			state = 1

			// Get the client's public key.
			A := m.n

			// Get the verifier mapped to the specified user I
			I := string(m.msg)
			v, ok := verifiers[I]
			if !ok {
				m.ok = ok
				m.err = errors.New("user not found")
				ch <- m
				close(ch)
				return
			}

			// Generate the server's private key b and public key B.
			b := genPrivateKeySRP(256)
			B := mod(add(mul(srp.k, v), exp(srp.g, b, srp.N)), srp.N)

			// Calculate the session key K
			u := new(big.Int).SetBytes(sha256Sum(append(A.Bytes(), B.Bytes()...)))
			S := exp(mul(A, exp(v, u, srp.N)), b, srp.N)
			K = sha256Sum(S.Bytes())

			// Send server hello.
			ch <- srpMsg{t: srpServerHello, n: B, msg: s, ok: true}
		case srpClientValidate:
			if state != 1 {
				m.ok = false
				m.err = errors.New("protocol error 2")
				ch <- m
				close(ch)
				return
			}

			// Validate the auth tokens
			tknC := m.msg
			tknS := sha256Sum(append(K, s...))
			msg := srpMsg{t: srpServerValidate}
			if bytes.Equal(tknC, tknS) {
				msg.ok = true
			} else {
				msg.ok = false
				msg.err = errors.New("password invalid")
			}

			// Send server validate.
			ch <- msg
			close(ch)
			return
		default:
			m.ok = false
			ch <- m
			close(ch)
			return
		}
	}
}

func sha256Sum(d []byte) []byte {
	a := sha256.Sum256(d)
	return a[:]
}

func genPrivateKeySRP(n int) *big.Int {
	ax := make([]byte, n)
	_, err := rand.Read(ax)
	if err != nil {
		cryptopals.PrintError(err)
		return nil
	}

	return new(big.Int).SetBytes(ax)
}

func add(a, b *big.Int) *big.Int {
	return new(big.Int).Add(a, b)
}

func sub(a, b *big.Int) *big.Int {
	return new(big.Int).Sub(a, b)
}

func mul(a, b *big.Int) *big.Int {
	return new(big.Int).Mul(a, b)
}

func mod(a, b *big.Int) *big.Int {
	return new(big.Int).Mod(a, b)
}

func exp(a, b, c *big.Int) *big.Int {
	return new(big.Int).Exp(a, b, c)
}
