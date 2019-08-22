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

func s4c30() {
	fmt.Println("Set 4, Challenge 30")

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
	o := MD4Oracle{Key: key}

	// Compute the MAC of the original message.
	msg := []byte("comment1=cooking MCs;userdata=foo;comment2= like a pound of bacon")
	msgmac := o.MD4MAC(msg)

	// Use the oracle to find the key length.
	foundKL := findKeyLengthMD4MAC(&o, msg, max_keylen)

	// Get the padding
	padding := cryptopals.GetMD4Padding(uint64(foundKL + len(msg)))

	// Extend the MAC with our modified msg.
	msg2 := []byte(";admin=true")
	blockLen := foundKL + len(msg) + len(padding)
	newmac := cryptopals.ExtendMD4MAC(msgmac, msg2, uint64(blockLen))

	// Create the newmsg.
	newmsg := make([]byte, len(msg))
	copy(newmsg, msg)
	newmsg = append(newmsg, padding...)
	newmsg = append(newmsg, msg2...)

	if o.ValidateMAC(newmac, newmsg) {
		cryptopals.PrintSuccess("MD4 MACs match")
		qs := url.PathEscape(string(newmsg))
		fmt.Println("  ", qs[:22]+"..."+qs[len(qs)-20:])
	} else {
		cryptopals.PrintFailure("MD4 MACs don't match")
	}
}

func findKeyLengthMD4MAC(o *MD4Oracle, msg []byte, maxKeyLen int) (keylen int) {
	keylen = -1
	mac := o.MD4MAC(msg)
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
		ha := cryptopals.ExtendMD4MAC(mac, []byte{}, uint64(blockSize*64))
		for kl := 0; kl < maxKeyLen+1; kl++ {
			// For each block size, we try different key lengths.
			p := cryptopals.GetMD4Padding(uint64(len(msg) + kl))
			hb := o.MD4MAC(append(msg, p...))
			if bytes.Equal(ha[:], hb[:]) {
				return kl
			}
		}
	}
}

type MD4Oracle struct {
	Key []byte
}

func (o *MD4Oracle) ValidateMAC(mac [16]byte, data []byte) bool {
	h := o.MD4MAC(data)
	return bytes.Equal(h[:], mac[:])
}

// This a a naive and broken MAC.
func (o *MD4Oracle) MD4MAC(msg []byte) [16]byte {
	var data []byte
	data = append(data, o.Key...)
	data = append(data, msg...)
	return cryptopals.SumMD4(data)
}
