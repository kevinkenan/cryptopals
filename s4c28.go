package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	cryptopals "github.com/kevinkenan/cryptopals/utils"
)

func s4c28() {
	fmt.Println("Set 4, Challenge 28")
	// Validate the MAC function.
	test := []byte("abc")
	h1 := sha1.Sum(test)
	h2 := cryptopals.SumSHA1(test)
	if !bytes.Equal(h1[:], h2[:]) {
		cryptopals.PrintError(errors.New("SHA-1 function produces wrong hash"))
		return
	}

	msg := []byte("The quick brown fox jumps over the lazy dog")
	msg2 := []byte("The quick brown fox jumps over the lazy dot")

	// Specify the keys
	key := make([]byte, 16)
	binary.BigEndian.PutUint64(key, 0x01)
	o := SHA1Oracle{Key: key}

	key2 := make([]byte, 16)
	binary.BigEndian.PutUint64(key2, 0x11)
	o2 := SHA1Oracle{Key: key2}

	// Show that a different msg creates a different MAC sum (the messages
	// differ by character).
	mac_msg2 := o.SHA1MAC(msg2)
	if o.ValidateMAC(mac_msg2, msg) {
		cryptopals.PrintFailure("MACs shouldn't match when the message changes")
		return
	}

	// Show that a different key creates a different MAC sum (the keys differ by
	// one byte).
	mac_key2 := o2.SHA1MAC(msg)
	if o.ValidateMAC(mac_key2, msg) {
		cryptopals.PrintFailure("MACs shouldn't match when the key changes")
		return
	}

	cryptopals.PrintSuccess("MAC resists modifications to the message and key.")

}

type SHA1Oracle struct {
	Key []byte
}

func (o *SHA1Oracle) ValidateMAC(mac [20]byte, data []byte) bool {
	h := o.SHA1MAC(data)
	return bytes.Equal(h[:], mac[:])
}

// This a a naive and broken MAC.
func (o *SHA1Oracle) SHA1MAC(msg []byte) [20]byte {
	var data []byte
	data = append(data, o.Key...)
	data = append(data, msg...)
	return cryptopals.SumSHA1(data)
}
