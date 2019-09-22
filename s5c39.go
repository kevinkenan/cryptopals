package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	cryptopals "github.com/kevinkenan/cryptopals/utils"
	"math/big"
)

func s5c39() {
	fmt.Println("Set 5, Challenge 39")
	msg := "test"

	// Initialize an RSA object and use it to encrypt and decrypt.
	rsa := newSimpleRSA(1024, 3)
	ciphertext := rsa.encrypt(msg)
	foundtext := rsa.decrypt(ciphertext)

	// Did it work?
	if foundtext == msg {
		cryptopals.PrintSuccess("RSA encrypted and decrypted successfully")
	} else {
		cryptopals.PrintFailure("RSA didn't work")
	}
}

// If we need to decrypt a message and we only have the public key, then we
// would create a simpleRSA object, set e and n, and call decrypt. Similarly, if
// we already have the private key, would set d and n and call encrypt.
type simpleRSA struct {
	b    int      // Size of primes in bits.
	p, q *big.Int // Primes
	n    *big.Int // Modulus (included with the public key)
	e, d *big.Int // Public and private keys
	et   *big.Int // Totient used to compute the private key
}

func newSimpleRSA(bits, e int) *simpleRSA {
	var err error
	one := big.NewInt(1)
	rsa := &simpleRSA{}
	rsa.b = bits
	rsa.e = big.NewInt(int64(e))

START:
	// Generate our first big prime.
	rsa.p, err = rand.Prime(rand.Reader, bits)
	if err != nil {
		cryptopals.PrintError(err)
		return nil
	}

	// Ensure that pt is relatively prime to e.
	pt := sub(rsa.p, one)
	if mod(pt, rsa.e).Int64() == 0 {
		goto START
	}

	// Generate our first big prime.
	rsa.q, err = rand.Prime(rand.Reader, bits)
	if err != nil {
		cryptopals.PrintError(err)
		return nil
	}

	// Ensure that qt is relatively prime to e.
	qt := sub(rsa.q, one)
	if mod(qt, rsa.e).Int64() == 0 {
		goto START
	}

	// Compute the RSA parameters.
	rsa.n = mul(rsa.p, rsa.q)
	rsa.et = mul(pt, qt)
	rsa.d = invmod(rsa.e, rsa.et)

	return rsa
}

func (rsa *simpleRSA) encrypt(message string) *big.Int {
	if rsa.e == nil || rsa.n == nil {
		cryptopals.PrintError(errors.New("rsa: private key components not set"))
	}

	m := new(big.Int).SetBytes([]byte(message))
	return exp(m, rsa.e, rsa.n)
}

func (rsa *simpleRSA) encryptRaw(message []byte) *big.Int {
	if rsa.e == nil || rsa.n == nil {
		cryptopals.PrintError(errors.New("rsa: private key components not set"))
	}

	m := new(big.Int).SetBytes(message)
	return exp(m, rsa.e, rsa.n)
}

func (rsa *simpleRSA) decrypt(ciphertext *big.Int) string {
	if rsa.d == nil || rsa.n == nil {
		cryptopals.PrintError(errors.New("rsa: public key components not set"))
	}

	return string(exp(ciphertext, rsa.d, rsa.n).Bytes())
}

func (rsa *simpleRSA) decryptRaw(ciphertext *big.Int) *big.Int {
	if rsa.d == nil || rsa.n == nil {
		cryptopals.PrintError(errors.New("rsa: public key components not set"))
	}

	return exp(ciphertext, rsa.d, rsa.n)
}

func (rsa *simpleRSA) getPublicKey() (e *big.Int, n *big.Int) {
	return rsa.e, rsa.n
}

// padAndSign first creates a SHA256 hash of message and then signs it.
func (rsa *simpleRSA) padAndSign(message []byte) *big.Int {
	if rsa.d == nil || rsa.n == nil {
		cryptopals.PrintError(errors.New("rsa: public key components not set"))
	}

	pm := rsa.addPadding(sha256Sum(message))
	m := new(big.Int).SetBytes(pm)
	return exp(m, rsa.d, rsa.n)
}

// ASN1 DER for SHA256 (from https://golang.org/src/crypto/rsa/pkcs1v15.go)
var SHA256Prefix = []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}

// addPadding creates a byte slice with PCKS#1 v1.15 padding preceding the hash.
// It assumes that SHA256 was used for the hash. The padding scheme is:
//     0x00 || 0x01 || ps || 0x00 || prefix || hash
// where ps is a sequence of 0xFF to make the total length equal to size.
func (rsa *simpleRSA) addPadding(hash []byte) []byte {
	size := rsa.n.BitLen() / 8 // in bytes

	// t consists of prefix || hash
	t := make([]byte, len(SHA256Prefix)+len(hash))
	copy(t, SHA256Prefix)
	copy(t[len(SHA256Prefix):], hash)

	b := make([]byte, size)
	b[1] = 0x01
	for i := 2; i < size-len(t)-1; i++ {
		b[i] = 0xff
	}

	copy(b[size-len(t):], t)

	return b
}
