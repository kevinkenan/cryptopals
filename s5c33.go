package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"fmt"
	cryptopals "github.com/kevinkenan/cryptopals/utils"
	"math/big"
)

func s5c33() {
	fmt.Println("Set 5, Challenge 33")

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

	// Initialize our key exchange struct for alice.
	alice := dhKeyExchange{}
	alice.Init(g, p)

	// Initialize our key exchange struct for bob.
	bob := dhKeyExchange{}
	bob.Init(g, p)

	// Exchange public keys between alice and bob.
	alice.Sync(bob.GetPublicKey())
	bob.Sync(alice.GetPublicKey())

	// Alice encrypts a message.
	plaintext := []byte("testing")
	ciphertext, err := alice.Encrypt(plaintext)
	if err != nil {
		cryptopals.PrintError(err)
		println("here")
		return
	}

	// Bob decrypts alice's message.
	foundtext, err := bob.Decrypt(ciphertext)
	if err != nil {
		cryptopals.PrintError(err)
		return
	}

	// Was the decryption successful?
	if bytes.Equal(plaintext, foundtext) {
		cryptopals.PrintSuccess("bob can decrypt messages from alice using diffie-hellman to exchange keys")
	} else {
		cryptopals.PrintFailure("key exchange didn't work")
	}
}

type dhKeyExchange struct {
	p, g, X, x, Y, s *big.Int
	iv, key          []byte
}

func (kex *dhKeyExchange) Init(g, p *big.Int) {
	kex.g = g
	kex.p = p

	x := generateSecret()
	X := new(big.Int)
	X.Exp(kex.g, x, kex.p)

	kex.x = x
	kex.X = X
}

func (kex *dhKeyExchange) isInitialized() (ok bool, err error) {
	ok = false
	if kex.g == nil {
		err = errors.New("initialization: g is nil")
		return
	}
	if kex.p == nil {
		err = errors.New("initialization: p is nil")
		return
	}
	if kex.x == nil {
		err = errors.New("initialization: x is nil")
		return
	}
	if kex.X == nil {
		err = errors.New("initialization: X is nil")
		return
	}

	return true, nil
}

func (kex *dhKeyExchange) Sync(Y *big.Int) {
	kex.Y = Y
}

func (kex *dhKeyExchange) isSynchronized() (bool, error) {
	if kex.Y == nil {
		return false, errors.New("not synchronized")
	}

	return true, nil
}

func (kex *dhKeyExchange) Encrypt(plaintext []byte) (ciphertext []byte, err error) {
	if ok, err := kex.isSynchronized(); !ok {
		return nil, err
	}

	// Calculate the session key.
	s := new(big.Int)
	s.Exp(kex.Y, kex.x, kex.p)
	ss := sha1.Sum(s.Bytes())
	key := ss[:16]

	// Generate the IV.
	iv := make([]byte, 16)
	_, err = rand.Read(iv)
	if err != nil {
		return nil, err
	}

	padded := cryptopals.Padding(plaintext, 16)
	ciphertext, err = cryptopals.EncryptAESwithCBC(padded, iv, key)
	if err != nil {
		return nil, err
	}
	ciphertext = append(iv, ciphertext...)

	return
}

func (kex *dhKeyExchange) Decrypt(ciphertext []byte) (plaintext []byte, err error) {
	if ok, err := kex.isSynchronized(); !ok {
		return nil, err
	}

	// Calculate the session key.
	s := new(big.Int)
	s.Exp(kex.Y, kex.x, kex.p)
	ss := sha1.Sum(s.Bytes())
	key := ss[:16]

	// Get the IV.
	iv := ciphertext[:16]

	// Decrypt
	plaintext, err = cryptopals.DecryptAESwithCBC(ciphertext[16:], iv, key)
	if err != nil {
		return nil, err
	}

	return
}

func (kex *dhKeyExchange) GetPublicKey() *big.Int {
	if ok, _ := kex.isInitialized(); !ok {
		return nil
	}

	newX := big.Int{}
	return newX.Set(kex.X)
}

func generateSecret() (a *big.Int) {
	ax := make([]byte, 32)
	_, err := rand.Read(ax)
	if err != nil {
		cryptopals.PrintError(err)
		return
	}
	a = new(big.Int)
	a.SetBytes(ax)
	return
}
