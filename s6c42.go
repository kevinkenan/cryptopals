package main

import (
	"bytes"
	"errors"
	"fmt"
	cryptopals "github.com/kevinkenan/cryptopals/utils"
	"math/big"
)

func s6c42() {
	fmt.Println("Set 6, Challenge 42")

	rsa := newSimpleRSA(1024, 3)

	// Test that the signing functions work.
	message := []byte("hi mom")
	c := rsa.padAndSign(message)
	if !validateSigBad(c, rsa, message) {
		cryptopals.PrintError(errors.New("validation failed in test"))
		return
	}

	// forged starts as a real signature with a truncated header. I used two
	// 0xff bytes in the header in order to make it align on eight-byte blocks
	// when printed using cryptopals.PrintHexBlocks().
	forged := make([]byte, 5)
	forged[1] = 0x01
	forged[2] = 0xff
	forged[3] = 0xff
	forged = append(forged, SHA256Prefix...)
	forged = append(forged, sha256Sum(message)...)

	// Append a sequence of 0xff bytes so that forged is as long as the modulus
	// in bytes. My intuition here is that we want forged to be a number big
	// enough that cubing its (imprecise) cube root will produce a number whose
	// most significant digits are the valid parts of the signature forged
	// above. Because of the header, forged is a 2033 bit number so any cube
	// root we take will produce a number whose cube is less than the modulus of
	// 2048, thus avoiding the key.
	modLen := rsa.n.BitLen() / 8 // length in bytes
	garbage := getPackedBytes(modLen - len(forged))
	forged = append(forged, garbage...)

	// Convert forged into a big int and find fcr, the cube root. Keep in mind
	// that fcr will almost certainly not be a perfect root.
	f := new(big.Int).SetBytes(forged)
	sig := cryptopals.RootBS(big.NewInt(3), f)

	// Does our forged signature, sig, pass the validation test?
	valid := validateSigBad(sig, rsa, message)
	if valid {
		cryptopals.PrintSuccess("forged a valid signature for 'hi mom'")
	} else {
		cryptopals.PrintFailure("forged signature didn't pass validation")
	}
}

func getPackedBytes(n int) []byte {
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = 0xff
	}

	return b
}

// validateSigBad is a bad implementation vulnerable to Bleichenbacher's e=3
// attack. It uses SHA256 as the hash function.
func validateSigBad(sig *big.Int, rsa *simpleRSA, msg []byte) bool {
	// "Decrypt" the signature sig.
	e, n := rsa.getPublicKey()
	s := exp(sig, e, n).Bytes()

	// Note that the first byte of s is not 0x00 as you might expect since that
	// was the first byte of the original padded message. When signing, the
	// padded message is converted to a big.Int which drops leading zeroes since
	// they add no information to a big.Int. Therefore, s is shorter than the
	// original message by one byte, and the first byte of s is the second byte
	// of the original.
	if s[0] != 0x01 {
		return false
	}

	// Check that there are 0xff bytes terminated by a 0x00 byte.
	var k int
LOOP:
	for k = 1; k < len(s); k++ {
		switch s[k] {
		case 0x00:
			k += 1
			break LOOP
		case 0xff:
			continue
		default:
			return false
		}
	}

	// Check that the standard ASN.1 SHA256 prefix is next.
	preLen := len(SHA256Prefix)
	if !bytes.Equal(s[k:k+preLen], SHA256Prefix) {
		return false
	}

	// Check that the correct hash value is at the end.
	hash := sha256Sum(msg)
	if !bytes.Equal(s[k+preLen:k+preLen+len(hash)], hash) {
		return false
	}

	return true
}
