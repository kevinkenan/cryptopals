package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	cryptopals "github.com/kevinkenan/cryptopals/utils"
	"math/big"
	rnd "math/rand"
	"strings"
	"time"
)

type srpMITM struct {
	ch chan string // The MITM will send the cracked password down this channel.
}

func s5c38() {
	fmt.Println("Set 5, Challenge 38")

	I := "username"
	// We assume that the user has selected a simple, guessable password.
	P := []byte(srpSelectSimplePassword())

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

	// Create the man-in-the-middle. To test the protocol without the MITM
	// comment out the 2nd line below so that mitm is nil.
	var mitm *srpMITM
	mitm = &srpMITM{ch: make(chan string)}

	// Open a channel to a simulated server with a mitm (who could be nil).
	ch := make(chan srpMsg)
	go srpSimplifiedServer(&srp, ch, mitm)

	// The client attempts to login.
	success := srpSimplifiedLogin(I, P, srp, ch)

	// The MITM attempts to recover the password and sends the result down the
	// mitm channel.
	// noinspection GoNilness
	if mitm != nil {
		password := <-mitm.ch
		if strings.Compare(string(P), password) == 0 {
			cryptopals.PrintSuccess("Cracked the password: " + password)
			return
		}
		cryptopals.PrintFailure("Didn't crack the password")
		return
	}

	// If there's no MITM just print the result of the login attempt.
	if success {
		fmt.Println("  Password was accepted")
	} else {
		fmt.Println("  Password was not accepted")
	}
}

func srpSimplifiedLogin(I string, P []byte, srp srpData, ch chan srpMsg) bool {
	var s, ub []byte
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
		lm := len(msg.msg) - 16
		s = msg.msg[:lm]
		ub = msg.msg[lm:]
		B = msg.n
	}

	// Calculate the session key K. Note here that u is a number sent from the
	// server and not the hash of A and B as it is in the normal SRP and the S
	// construction is considerably less complicated.
	u := new(big.Int).SetBytes(ub)
	x := new(big.Int).SetBytes(sha256Sum(append(s, P...)))
	S := exp(B, add(a, mul(u, x)), srp.N)
	K := sha256Sum(S.Bytes())

	// Calculate the auth token
	tkn := sha256Sum(append(K, s...))

	// Send client validate
	ch <- srpMsg{t: srpClientValidate, msg: tkn}

	// Does the password let us login?
	if msg := <-ch; msg.ok && msg.t == srpServerValidate {
		return true
	} else {
		return false
	}
}

// This function simulates the server side of our SRP implementation. It
// receives and responds to messages.
func srpSimplifiedServer(srp *srpData, ch chan srpMsg, mitm *srpMITM) {
	var err error
	var s, K []byte
	var A, B *big.Int
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
			A = m.n

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

			// Generate the server's private key b and public key B. Note that B
			// in this simplified algorithm doesn't include the verifier, which
			// in the original algorithm mixed the password into B.
			b := genPrivateKeySRP(256)
			B = exp(srp.g, b, srp.N)

			// Generate a random number ub.
			ub := make([]byte, 16)
			_, err = rand.Read(ub)
			if err != nil {
				cryptopals.PrintError(err)
				return
			}

			// Convert ub to a big integer u. This is the key difference of this
			// simplified SRP: u is a random number rather than the hash of A
			// and B.
			u := new(big.Int).SetBytes(ub)

			// Calculate the session key K.
			S := exp(mul(A, exp(v, u, srp.N)), b, srp.N)
			K = sha256Sum(S.Bytes())

			// Pack the salt and u together to make it easy to send both back to
			// the client in the srpMsg.msg field.
			su := append(s, ub...)

			// Send server hello.
			msg := srpMsg{t: srpServerHello, n: B, msg: su, ok: true}

			// MITM does his nefarious deeds if he exists.
			if mitm != nil {
				b = big.NewInt(1)
				B = exp(srp.g, b, srp.N)
				ub, _ := hex.DecodeString("00000000000000000000000000000001")
				su = append(s, ub...)
				msg.n = B
				msg.msg = su
			}

			ch <- msg
		case srpClientValidate:
			if state != 1 {
				m.ok = false
				m.err = errors.New("protocol error 2")
				ch <- m
				close(ch)
				return
			}

			// Because the MITM set both b and u to 1, the client's auth token
			// tknC is B^(a+ux) = g^(a+x) = A*g^x. The MITM has already
			// intercepted A, and x is calculated easily from the salt, which is
			// also know to the MITM, and the password. So the MITM has all the
			// information needed to brute force the password offline, by
			// guessing passwords, calculating A*g^x, and then comparing it to
			// the captured tknC.
			tknC := m.msg
			if mitm != nil {
				go func() {
					for _, p := range srpPasswords {
						x := new(big.Int).SetBytes(sha256Sum(append(s, []byte(p)...)))
						S := mod(mul(A, exp(srp.g, x, srp.N)), srp.N)
						K := sha256Sum(S.Bytes())
						tknGuess := sha256Sum(append(K, s...))
						if bytes.Equal(tknC, tknGuess) {
							mitm.ch <- p
							return
						}
					}
					mitm.ch <- ""
				}()
			}

			// Validate the auth tokens
			msg := srpMsg{t: srpServerValidate}
			tknS := sha256Sum(append(K, s...))
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

func (msg *srpMsg) Copy() srpMsg {
	newmsg := *msg
	newmsg.msg = make([]byte, len(msg.msg))
	copy(newmsg.msg, msg.msg)
	return newmsg
}

var (
	// This is our simple password dictionary. In a real attack we would use
	// /usr/share/dict/words or some other large dictionary.
	srpPasswords = []string{"answer", "astonishing", "battle", "birth", "blush",
		"broad", "can", "capricious", "cars", "certain", "check", "cheese",
		"cobweb", "crash", "curve", "cute", "damage", "deeply", "degree",
		"diligent", "disagree", "discreet", "double", "dry", "dysfunctional",
		"earthquake", "educate", "educated", "elated", "elbow", "elegant",
		"endurable", "fast", "fetch", "frantic", "gentle", "grandmother",
		"guiltless", "heat", "hilarious", "homeless", "hospital", "hover",
		"hurried", "hushed", "instruct", "jump", "laughable", "letter", "living",
		"low", "marked", "marvelous", "mint", "mixed", "morning", "move", "mug",
		"north", "note", "offer", "petite", "picayune", "pig", "plantation",
		"proud", "rainstorm", "reward", "rhetorical", "roasted", "robin", "roll",
		"salty", "side", "sigh", "sign", "simplistic", "sniff", "sort", "spark",
		"stitch", "stone", "stormy", "substance", "sugar", "tangy", "tense", "true",
		"undesirable", "use", "various", "vase", "volleyball", "wander", "waves",
		"weigh", "wide-eyed", "wipe", "wreck", "wrist"}
)

func srpSelectSimplePassword() string {
	rnd.Seed(time.Now().Unix())
	return srpPasswords[rnd.Intn(len(srpPasswords))]
}
