package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	cryptopals "github.com/kevinkenan/cryptopals/utils"
)

func s4c28() {
	fmt.Println("Set 4, Challenge 28")
	msg := []byte("The quick brown fox jumps over the lazy dog")
	msg2 := []byte("The quick brown fox jumps over the lazy dot")

	// Specify the keys
	key := make([]byte, 16)
	binary.BigEndian.PutUint64(key, 0x01)
	key2 := make([]byte, 16)
	binary.BigEndian.PutUint64(key2, 0x11)

	// Compute the MAC
	mac := cryptopals.SHA1MAC(key, msg)

	// Show that a one-character change in the msg creates a different
	// MAC sum.
	mac_msg2 := cryptopals.SHA1MAC(key, msg2)
	if bytes.Equal(mac[:], mac_msg2[:]) {
		cryptopals.PrintFailure("MACs shouldn't match")
		return
	}

	// Show that a one-character change in the key creates a different
	// MAC sum.
	mac_key2 := cryptopals.SHA1MAC(key, msg2)
	if bytes.Equal(mac[:], mac_key2[:]) {
		cryptopals.PrintFailure("MACs shouldn't match")
		return
	}

	cryptopals.PrintSuccess("MAC resists modifications to the message and key.")

}
