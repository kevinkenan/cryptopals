package main

import (
	"bytes"
	"errors"
	"fmt"
	cryptopals "github.com/kevinkenan/cryptopals/utils"
	"math/big"
)

func s5c35() {
	fmt.Println("Set 5, Challenge 35")

	p := new(big.Int)
	p.SetString("0x"+
		"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"+
		"e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"+
		"3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"+
		"6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"+
		"24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"+
		"c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"+
		"bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"+
		"fffffffffffff", 0)

	// Set g = 1.
	if ok := mitmDHGroup(big.NewInt(1), p); ok {
		cryptopals.PrintSuccess("man-in-the-middle was able to read encrypted texts when g = 1")
	} else {
		cryptopals.PrintFailure("man-in-the-middle was not able to read encrypted texts when g = 1")
	}

	// Set g = p.
	if ok := mitmDHGroup(p, p); ok {
		cryptopals.PrintSuccess("man-in-the-middle was able to read encrypted texts when g = p")
	} else {
		cryptopals.PrintFailure("man-in-the-middle was not able to read encrypted texts when g = p")
	}

	// Set g = p-1.
	pp := big.NewInt(0).Add(p, big.NewInt(-1)) // pp = p-1
	if ok := mitmDHGroupX(pp, p); ok {
		cryptopals.PrintSuccess("man-in-the-middle was able to read encrypted texts when g = p-1")
	} else {
		cryptopals.PrintFailure("man-in-the-middle was not able to read encrypted texts when g = p-1")
	}
}

// This function attacks diffie-hellman when someone has changed g to 1 or p.
func mitmDHGroup(g, p *big.Int) bool {
	// This mitm function doesn't change anything, but I wanted to reuse code
	// from challenge 34.
	mitm := func(msg *dhMsg) dhMsg {
		return msg.Copy()
	}

	// Open a channel to a simulated Bob.
	bobch := make(chan dhMsg)
	go bob(bobch, mitm)

	// Perform the key exchange.
	kex := dhProtocol(bobch, g, p, mitm)

	// Encrypt the message.
	plaintext := []byte("hello")
	ciphertext, err := kex.Encrypt(plaintext)
	if err != nil {
		cryptopals.PrintError(err)
		return false
	}

	// The man-in-the-middle can forge his own dhKeyExchange since he changed g
	// to a value that always produces a known value. When g = 1, g^(xy) is
	// equal to 1 and when g = p, g^(xy) is 0 (because we're working mod p). So
	// we forge a dhKeyExchange struct and set the secret private key x to 1 so
	// that we can craft Y to produce the correct session key.
	mitmKex := dhKeyExchange{}
	mitmKex.Init(g, p)
	one := big.NewInt(1)
	mitmKex.x = one

	switch {
	case g.Cmp(one) == 0:
		mitmKex.Y = one
	case g.Cmp(p) == 0:
		mitmKex.Y = big.NewInt(0)
	default:
		cryptopals.PrintError(errors.New("g is not valid for this attack"))
		return false
	}

	// The man-in-the-middle can now decrypt messages encrypted with the
	// diffie-hellman session key.
	ourtext, err := mitmKex.Decrypt(ciphertext)
	if err != nil {
		cryptopals.PrintError(err)
		return false
	}

	// Send the ciphertext to Bob.
	bobch <- mitm(&dhMsg{t: dhSendMsg, msg: ciphertext})

	// Receive Bob's response.
	ans := <-bobch
	if !ans.ok {
		cryptopals.PrintError(ans.err)
		return false
	}

	// The MITM can decrypt Bob's message.
	bobtext, err := mitmKex.Decrypt(ans.msg)
	if err != nil {
		cryptopals.PrintError(err)
		return false
	}

	// Test if the decryptions are correct.
	if bytes.Equal(bobtext, []byte("hi")) && bytes.Equal(ourtext, []byte("hello")) {
		return true
	}

	return false
}

// This function attacks diffie-hellman when someone has changed g to p-1.
func mitmDHGroupX(g, p *big.Int) bool {
	// This mitm function doesn't change anything, but I wanted to reuse code
	// from challenge 34.
	mitm := func(msg *dhMsg) dhMsg {
		return msg.Copy()
	}

	// Open a channel to a simulated Bob.
	bobch := make(chan dhMsg)
	go bob(bobch, mitm)

	// Perform the key exchange.
	kex := dhProtocol(bobch, g, p, mitm)

	// Encrypt the message.
	plaintext := []byte("hello")
	ciphertext, err := kex.Encrypt(plaintext)
	if err != nil {
		cryptopals.PrintError(err)
		return false
	}

	// Because g = p-1, we know the subgroup it generates is {1, p-1}. Therefore
	// kex.X and kex.Y must be 1 or p-1 and the resulting secret g^(xy) must be
	// 1 or p-1. Since a man-in-the-middle can view X and Y on the wire, they
	// have enough information to determine which of those two values the key
	// actually is. So we "forge" a dhKeyExchange struct and set the secret
	// private key x to 1 so that we can craft Y to produce the correct session
	// key.
	mitmKex := dhKeyExchange{}
	mitmKex.Init(g, p)
	one := big.NewInt(1)
	mitmKex.x = one
	pp := big.NewInt(0).Add(p, big.NewInt(-1)) // pp = p-1

	switch {
	case kex.X.Cmp(one)+kex.Y.Cmp(one) < 2:
		// If either X or Y is 1, then the session key is 1.
		mitmKex.Y = one
	case kex.X.Cmp(pp)+kex.Y.Cmp(pp) == 0:
		// If both X and Y are p-1, then the session key is p-1.
		mitmKex.Y = pp
	default:
		cryptopals.PrintError(errors.New("g is not valid for this attack"))
		return false
	}

	// The man-in-the-middle can now decrypt messages encrypted with the
	// diffie-hellman session key.
	ourtext, err := mitmKex.Decrypt(ciphertext)
	if err != nil {
		cryptopals.PrintError(err)
		return false
	}

	// Send the ciphertext to Bob.
	bobch <- mitm(&dhMsg{t: dhSendMsg, msg: ciphertext})

	// Receive Bob's response.
	ans := <-bobch
	if !ans.ok {
		cryptopals.PrintError(ans.err)
		return false
	}

	// The MITM can decrypt Bob's messages, too.
	bobtext, err := mitmKex.Decrypt(ans.msg)
	if err != nil {
		cryptopals.PrintError(err)
		return false
	}

	// Test if the decryptions are correct.
	if bytes.Equal(bobtext, []byte("hi")) && bytes.Equal(ourtext, []byte("hello")) {
		return true
	}

	return false
}
