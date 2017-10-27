package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/kevinkenan/cryptopals/utils"
)

func s3c17() {
	fmt.Println("Set 3, Challenge 17")
	var err error

	blockSize := 16

	b64Strings := []string{
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"}

	// Generate a random key.
	key := make([]byte, 16)
	_, err = rand.Read(key)
	if err != nil {
		cryptopals.PrintError(err)
		return
	}

	// Generate a random iv.
	iv := make([]byte, 16)
	_, err = rand.Read(iv)
	if err != nil {
		cryptopals.PrintError(err)
		return
	}

	o := c17oracle{Key: key, IV: iv}
	success := true
	for _, ss := range b64Strings {
		s, _ := base64.StdEncoding.DecodeString(ss)

		// Create the ciphertext and prepend the iv.
		ciphertext := make([]byte, blockSize)
		copy(ciphertext, iv)
		encrypted, err := o.encrypt(s)
		ciphertext = append(ciphertext, encrypted...)

		// Break the encryption and store the cleartext.
		blockCount := len(ciphertext)/blockSize - 1
		cleartext := make([]byte, blockCount*blockSize)
		for block := 0; block < blockCount; block++ {
			// We pass two blocks to the breakCbc... function which returns
			// the cleartext of the second block.
			c, _ := breakCbcBlockWithPaddingOracle(ciphertext[block*blockSize:(block+1)*blockSize+blockSize], o)
			copy(cleartext[block*blockSize:(block+1)*blockSize], c[:blockSize])
		}

		// The cleartext may be padded so we strip it clean.
		unpadded, err := cryptopals.StripPadding(cleartext, blockSize)
		if err != nil {
			cryptopals.PrintError(err)
			return
		}

		if !bytes.Equal(unpadded, s) {
			success = false
			break
		}
	}

	if success {
		cryptopals.PrintSuccess("Decrypted all ten strings")
	} else {
		cryptopals.PrintFailure("")
	}
}

// This function uses a padding oracle and 32 bytes of ciphertext to recover
// the last 16 bytes of the ciphertext.
func breakCbcBlockWithPaddingOracle(ciphertext []byte, o c17oracle) ([]byte, error) {
	if len(ciphertext) != 32 {
		return nil, errors.New("Wrong number of bytes passed to breakCbcBlockWithPaddingOracle")
	}

	// We keep the ciphertext untouched and instead copy it into targettext to
	// break the crypto.
	targettext := make([]byte, 32)
	copy(targettext, ciphertext)
	stagedtext := make([]byte, 16)

	// Prebuild a slice containing the bytes we'll use to attack the byte
	// isolated by the probe in the attack window.
	allBytes := make([]byte, 256)
	for n := 0; n < 256; n++ {
		allBytes[n] = byte(n)
	}

	// We iterate over the last 16 bytes of the cipherblock, working on one
	// byte at a time, starting with the last byte.
	for i := 15; i >= 0; i-- {
		// We try each possible byte looking for one that will produce valid
		// padding.
		for _, b := range allBytes {
			// Set the target byte i to the byte b we're testing.
			targettext[i] = b
			targetpadding := byte(15 - i + 1)
			for j := 15; j > i; j-- {
				targettext[j] = stagedtext[j] ^ targetpadding
			}

			// Check to see if it produces valid padding.
			paddingIsValid, err := o.isPaddingValid(targettext)
			if err != nil {
				cryptopals.PrintError(err)
				continue
			}
			if paddingIsValid {
				// If the target byte i is the last byte (byte 15), we may
				// have the right byte or we may have stumbled onto a byte
				// that just happens to produce valid padding when combined
				// with byte 14 and the rest of the block. So we alter byte 14
				// and if it still produces valid padding we know we have the
				// right byte.
				if i == 15 {
					targettext[14] = ciphertext[14] ^ targetpadding
					paddingIsValid, err = o.isPaddingValid(targettext)
					if err != nil {
						fmt.Printf("%02x\n", b)
						cryptopals.PrintError(err)
						continue
					}

					if paddingIsValid {
						// Padding is valid so we set stagedtext and break out
						// of the loop.
						stagedtext[i] = b ^ targetpadding
						break
					} else {
						// The padding is not valid, so we reset the 14th byte
						// of the targettext and continue with the next test
						// byte b.
						targettext[14] = ciphertext[14]
					}
				} else {
					// This isn't the last byte so the valid padding is a
					// correct indicator.
					stagedtext[i] = b ^ targetpadding
					break
				}
			}
		}
	}

	// XOR the stagedtext with the ciphertext to produce the plaintext.
	cleartext, _ := cryptopals.XorByteArrays(stagedtext, ciphertext[:16])

	return cleartext, nil
}

type c17oracle struct {
	Key, IV []byte
}

func (o c17oracle) isPaddingValid(ciphertext []byte) (bool, error) {
	_, err := cryptopals.DecryptAESwithCBC(ciphertext, o.IV, o.Key)

	if err != nil {
		if err.Error() == "Invalid padding" || err.Error() == "Wrong number of padding bytes" {
			return false, nil
		} else {
			return false, err
		}
	}

	return true, nil
}

func (o c17oracle) decrypt(ciphertext []byte) ([]byte, error) {
	plaintext, err := cryptopals.DecryptAESwithCBC(ciphertext, o.IV, o.Key)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func (o c17oracle) encrypt(plaintext []byte) ([]byte, error) {
	ciphertext, err := cryptopals.EncryptAESwithCBC(cryptopals.Padding(plaintext, 16), o.IV, o.Key)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}
