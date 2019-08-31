package main

import (
	"bytes"
	"errors"
	"fmt"
	cryptopals "github.com/kevinkenan/cryptopals/utils"
	"math/big"
)

const (
	dhSendG int = iota
	dhAckG
	dhSendP
	dhAckP
	dhSendX
	dhAckX
	dhSendY
	dhSendMsg
)

type dhMsg struct {
	n   *big.Int // Diffie-Hellman variables
	t   int      // Step in the protocol
	msg []byte   // Message
	ok  bool     // true if the message was processed correctly
	err error    // Populated if ok = false.
}

func (msg *dhMsg) Copy() dhMsg {
	newmsg := *msg
	newmsg.msg = make([]byte, len(msg.msg))
	copy(newmsg.msg, msg.msg)
	return newmsg
}

type mitmFunc func(msg *dhMsg) dhMsg

func s5c34() {
	fmt.Println("Set 5, Challenge 34")

	g := big.NewInt(2)
	p := new(big.Int)
	p.SetString(
		"0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"+
			"e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"+
			"3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"+
			"6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"+
			"24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"+
			"c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"+
			"bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"+
			"fffffffffffff", 0)

	if ok := simpleDH(g, p); ok {
		cryptopals.PrintSuccess("diffie-hellman protocol works")
	} else {
		cryptopals.PrintFailure("diffie-hellman protocol is broken")
	}

	if ok := mitmDH(g, p); ok {
		cryptopals.PrintSuccess("man-in-the-middle was able to read encrypted texts")
	} else {
		cryptopals.PrintFailure("man-in-the-middle was not able to read encrypted texts")
	}
}

// This function executes diffie-hellman as is with no attacks.
func simpleDH(g, p *big.Int) bool {
	// The mitm doesn't change any of the messages. This is equivalent to no
	// man-in-the-middle.
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

	// Send the ciphertext to Bob.
	bobch <- mitm(&dhMsg{t: dhSendMsg, msg: ciphertext})

	// Receive Bob's response.
	ans := <-bobch
	if !ans.ok {
		cryptopals.PrintError(ans.err)
		return false
	}

	// Decrypt Bob's message.
	newtext, err := kex.Decrypt(ans.msg)
	if err != nil {
		cryptopals.PrintError(err)
		return false
	}

	if bytes.Equal(newtext, []byte("hi")) {
		return true
	}

	return false
}

// This function simulates a man-in-the-middle attack which changes the public
// keys to p.
func mitmDH(g, p *big.Int) bool {
	// Changes the public keys to p.
	mitm := func(msg *dhMsg) dhMsg {
		newMsg := msg.Copy()

		if msg.t == dhSendX || msg.t == dhSendY {
			newMsg.n = p
		}

		return newMsg
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

	// The man-in-the-middle can forge his own dhKeyExchange since he changed
	// both public keys to p.
	mitmKex := dhKeyExchange{}
	mitmKex.Init(g, p)
	mitmKex.X = p
	mitmKex.Y = p

	// The man-in-the-middle can now decrypt messages encrypted with the
	// diffie-hellman session key.
	foundtext, err := mitmKex.Decrypt(ciphertext)
	if err != nil {
		cryptopals.PrintError(err)
		return false
	}

	if bytes.Equal(foundtext, plaintext) {
		return true
	}

	return false
}

// dhProtocol simulates a DH key exchange using channel ch. The mitm function
// processes dhMsg objects as if a man-in-the-middle were intercepting and
// modifying the messages.
func dhProtocol(ch chan dhMsg, g, p *big.Int, mitm mitmFunc) *dhKeyExchange {
	// Initialize our key exchange struct.
	kex := dhKeyExchange{}
	kex.Init(g, p)

	// Send p to Bob.
	ch <- mitm(&dhMsg{n: kex.p, t: dhSendP})
	if ack := <-ch; !ack.ok {
		cryptopals.PrintError(ack.err)
		return nil
	}

	// Send g to Bob.
	ch <- mitm(&dhMsg{n: kex.g, t: dhSendG})
	if ack := <-ch; !ack.ok {
		cryptopals.PrintError(ack.err)
		return nil
	}

	// Send X to Bob.
	ch <- mitm(&dhMsg{n: kex.X, t: dhSendX})
	if ack := <-ch; !ack.ok {
		cryptopals.PrintError(ack.err)
		return nil
	}

	// Receive Y from Bob.
	if msg := <-ch; !msg.ok {
		cryptopals.PrintError(msg.err)
		return nil
	} else {
		kex.Sync(msg.n)
	}

	return &kex
}

// This function simulates Bob. It receives and responds to messages. The
// function supports man-in-the-middle attacks against messages from Bob.
func bob(ch chan dhMsg, mitm mitmFunc) {
	kex := dhKeyExchange{}
	state := 0
	for {
		switch m := <-ch; m.t {
		case dhSendP:
			if state != 0 {
				m.ok = false
				m.err = errors.New("protocol error 1")
				ch <- m
				close(ch)
				return
			}

			kex.p = m.n
			state = 1
			m.t = dhAckP
			m.ok = true
			ch <- mitm(&m)
		case dhSendG:
			if state != 1 {
				m.ok = false
				m.err = errors.New("protocol error 2")
				ch <- m
				close(ch)
				return
			}

			kex.Init(m.n, kex.p)
			state = 2
			m.t = dhAckG
			m.ok = true
			ch <- mitm(&m)
		case dhSendX:
			if state != 2 {
				m.ok = false
				m.err = errors.New("protocol error 3")
				ch <- m
				close(ch)
				return
			}

			kex.Sync(m.n)
			state = 3
			m.t = dhAckX
			m.ok = true
			ch <- mitm(&m)

			key := kex.X
			ch <- mitm(&dhMsg{n: key, t: dhSendY, ok: true})
		case dhSendMsg:
			if state != 3 {
				m.ok = false
				m.err = errors.New("protocol error 4")
				ch <- m
				close(ch)
				return
			}

			plaintext, err := kex.Decrypt(m.msg)
			if err != nil {
				m.ok = false
				m.err = err
				ch <- m
				return
			}

			msg := []byte("what?")
			if bytes.Equal(plaintext, []byte("hello")) {
				msg = []byte("hi")
				state = 4
			}

			ciphertext, err := kex.Encrypt(msg)
			if err != nil {
				m.ok = false
				m.err = err
				ch <- m
				return
			}

			ch <- mitm(&dhMsg{ok: true, msg: ciphertext, t: dhSendMsg})
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
