package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	cryptopals "github.com/kevinkenan/cryptopals/utils"
	rnd "math/rand"
	"net/url"
	"time"
)

func s4c29() {
	fmt.Println("Set 4, Challenge 29")

	// Create a random key no bigger than max_keylen bytes.
	max_keylen := 64
	rnd.Seed(time.Now().UnixNano())
	keylen := rnd.Intn(max_keylen) + 1
	//keylen = 48
	key := make([]byte, keylen)
	_, err := rand.Read(key)
	if err != nil {
		cryptopals.PrintError(err)
		return
	}

	// Initialize a SHA-1 Oracle with the key.
	o := SHA1Oracle{Key: key}

	// Compute the MAC of the original message.
	msg := []byte("comment1=cooking MCs;userdata=foo;comment2= like a pound of bacon")
	msgmac := o.SHA1MAC(msg)

	// Use the oracle to find the key length.
	foundKL := findKeyLengthSHA1MAC(&o, msg, max_keylen)

	// Get the padding
	padding := cryptopals.GetSHA1Padding(uint64(foundKL + len(msg)))

	// Extend the MAC with our modified msg.
	msg2 := []byte(";admin=true")
	blockLen := foundKL + len(msg) + len(padding)
	newmac := cryptopals.ExtendSHA1MAC(msgmac, msg2, uint64(blockLen))

	// Create the newmsg.
	newmsg := make([]byte, len(msg))
	copy(newmsg, msg)
	newmsg = append(newmsg, padding...)
	newmsg = append(newmsg, msg2...)

	if o.ValidateMAC(newmac, newmsg) {
		cryptopals.PrintSuccess("MACs match")
		qs := url.PathEscape(string(newmsg))
		fmt.Println("  ", qs[:22]+"..."+qs[len(qs)-20:])
	} else {
		cryptopals.PrintFailure("MACs don't match")
	}
}

func findKeyLengthSHA1MAC(o *SHA1Oracle, msg []byte, maxKeyLen int) (keylen int) {
	keylen = -1
	mac := o.SHA1MAC(msg)
	blockSize := len(msg) / 64

	for i := 0; ; i++ {
		// In order to extend the SHA-1 MAC we need to know how many 64-byte
		// blocks the concatenation of the key and the message fill. Since
		// we don't know the size of the key, we'll test many different
		// block sizes.
		maxBlocks := 1 + (len(msg) / 64) + (maxKeyLen / 64)
		if i > maxBlocks {
			return -1
		}

		blockSize += 1
		ha := cryptopals.ExtendSHA1MAC(mac, []byte{}, uint64(blockSize*64))
		for kl := 0; kl < maxKeyLen+1; kl++ {
			// For each block size, we try different key lengths.
			p := cryptopals.GetSHA1Padding(uint64(len(msg) + kl))
			hb := o.SHA1MAC(append(msg, p...))
			if bytes.Equal(ha[:], hb[:]) {
				return kl
			}
		}
	}
}
