package cryptopals

import (
	// "bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"sort"
)

func stopTheComplainingAboutFmt() {
	fmt.Println("")
}


func DetectAESMode(ciphertext []byte) string {
	// We use the blockSet map as a poor man's set.
	blockSet := make(map[string]int)
	blockCount := len(ciphertext) / aes.BlockSize
	for i := 0; i < blockCount; i++ {
		block := hex.EncodeToString(ciphertext[i*aes.BlockSize : (i+1)*aes.BlockSize])
		blockSet[block] = 0
	}

	// If the length of the map is less than the number of blocks, then at
	// least one of the blocks was duplicated.
	var encryptionType string
	if len(blockSet) != blockCount {
		encryptionType = "ECB"
	} else {
		encryptionType = "CBC"
	}

	return encryptionType
}


func Padding(in []byte, size int) []byte {
	padLen := size - (len(in) % size)
	padding := make([]byte, padLen)
	for i, _ := range padding {
		padding[i] = byte(padLen)
	}
	return append(in, padding...)
}


func EncryptAESwithECB(plaintext, key []byte) ([]byte, error) {
	// Create the cipher with the key.
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Encrypt each block of the plaintext.
	blockCount := len(plaintext) / aes.BlockSize
	ciphertext := make([]byte, blockCount*16)
	for i := 0; i < blockCount; i++ {
		blockStart := i * aes.BlockSize
		blockEnd := (i + 1) * aes.BlockSize
		cipher.Encrypt(ciphertext[blockStart:blockEnd], plaintext[blockStart:blockEnd])
	}

	return ciphertext, nil
}


func DecryptAESwithECB(ciphertext, key []byte) ([]byte, error) {
	// Create the cipher with the key.
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Decrypt each block of the ciphertext.
	blockCount := len(ciphertext) / aes.BlockSize
	cleartext := make([]byte, blockCount*aes.BlockSize)
	for i := 0; i < blockCount; i++ {
		blockStart := i * aes.BlockSize
		blockEnd := (i + 1) * aes.BlockSize
		cipher.Decrypt(cleartext[blockStart:blockEnd], ciphertext[blockStart:blockEnd])
	}

	// Discard padding.
	p := cleartext[len(cleartext)-1]
	cleartext = cleartext[0:len(cleartext)-int(p)]

	return cleartext, nil
}


func EncryptAESwithCBC(plaintext, iv, key []byte) ([]byte, error) {
	// Create the cipher with the key.
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Encrypt each block of the plaintext.
	blockCount := len(plaintext) / aes.BlockSize
	ciphertext := make([]byte, blockCount*aes.BlockSize)
	cipherBlock := iv
	for i := 0; i < blockCount; i++ {
		blockStart := i * aes.BlockSize
		blockEnd := (i + 1) * aes.BlockSize

		// Mix in the cipherblock by XORing it with the plaintext
		for i, x := range plaintext[blockStart:blockEnd] {
			plaintext[blockStart+i] = x ^ cipherBlock[i]
		}

		// Encrypt the block.
		cipher.Encrypt(ciphertext[blockStart:blockEnd], plaintext[blockStart:blockEnd])

		// The resulting encrypted block is the new cipherblock
		cipherBlock = ciphertext[blockStart:blockEnd]
	}

	return ciphertext, nil
}


func DecryptAESwithCBC(ciphertext, iv, key []byte) ([]byte, error) {
	// Create the cipher with the key.
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Decrypt each block of the ciphertext.
	blockCount := len(ciphertext) / aes.BlockSize
	cleartext := make([]byte, blockCount*aes.BlockSize)
	cipherBlock := iv
	for i := 0; i < blockCount; i++ {
		blockStart := i * aes.BlockSize
		blockEnd := (i + 1) * aes.BlockSize
		cipher.Decrypt(cleartext[blockStart:blockEnd], ciphertext[blockStart:blockEnd])
		for i, x := range cleartext[blockStart:blockEnd] {
			cleartext[blockStart+i] = x ^ cipherBlock[i]
		}
		cipherBlock = ciphertext[blockStart:blockEnd]
	}

	return cleartext, nil
}


func HexStringToBase64(hs string) (string, error) {
	data, err := hex.DecodeString(hs)
	return base64.StdEncoding.EncodeToString(data), err
}


func HammingDistance(a, b []byte) (int, error) {
	out, err := XorByteArrays(a, b)
	if err != nil {
		return 0, err
	}

	totalOnes := 0
	for _, b := range out {
		totalOnes += bits.OnesCount(uint(b))
	}

	return totalOnes, nil
}


func RepeatedKeyXor(plaintext, keySeed []byte) ([]byte, error) {
	ptxtLen := len(plaintext)
	keyLen := len(keySeed)

	// The key is the keySeed repeated over and over until it matches the
	// length of the plaintext.
	key :=  make([]byte, ptxtLen)
	for i := range plaintext {
		key[i] = keySeed[i%keyLen]
	}

	// Encrypt and return the ciphertext.
	return XorByteArrays(plaintext, key)
}

// Returns a byte slice containing every incr byte starting with start.
func BytePart(b []byte, start, incr int) ([]byte, error) {
	if incr <= 0 {
		return nil, errors.New("invalid increment value")
	}
	if start < 0 || start > len(b) {
		return nil, errors.New("invalid start value")
	}
	part := make([]byte, len(b)/incr)
	for i := 0; i < len(part); i++ {
		part[i] = b[start+(i*incr)]
	}
	return part, nil
}

// Finds likely key sizes
func KeyLengthSearchRepeatedKeyXOR(ciphertext []byte, maxLength int) (KeyLengthScores, error) {

	var scores KeyLengthScores
	for keyLen := 2; keyLen <= maxLength; keyLen++ {
		a := ciphertext[:keyLen]
		b := ciphertext[keyLen:2*keyLen]
		c := ciphertext[2*keyLen:3*keyLen]
		d := ciphertext[3*keyLen:4*keyLen]

		// diff, err := XorByteArrays(a, b)
		// if err != nil {
		// 	return 0, err
		// }

		dist1, err := HammingDistance(a, b)
		if err != nil {
			return scores, err
		}

		dist2, err := HammingDistance(a, c)
		if err != nil {
			return scores, err
		}

		dist3, err := HammingDistance(a, d)
		if err != nil {
			return scores, err
		}

		dist := (float64(dist1) + float64(dist2) + float64(dist3))/(3.0*float64(keyLen))

		scores = append(scores, KeyLengthScore{keyLen, dist})
		// fmt.Println(string(a))
		// fmt.Println(string(b))
		// fmt.Println(string(c))
		// fmt.Println(string(d))
		// fmt.Println("dist: ", float64(dist)/float64(keyLen))
	}

	sort.Sort(scores)

	return scores, nil
}


func GetPrintableASCIIBytes() []byte {
	ascii := make([]byte, 96)
	for i := 32; i < 127; i++ {
		ascii[i-32] = byte(i)
	}
	return ascii
}

type KeyLengthScore struct {
	KeyLength int
	Score float64
}

type KeyLengthScores []KeyLengthScore

// Functions to implement sort.Interface
func (k KeyLengthScores) Len() int           { return len(k) }
func (k KeyLengthScores) Less(i, j int) bool { return k[i].Score < k[j].Score }
func (k KeyLengthScores) Swap(i, j int)      { k[i], k[j] = k[j], k[i] }


func XorByteArrays(a, b []byte) ([]byte, error) {
	out := make([]byte, len(a))
	if len(a) != len(b) {
		return out, ErrUnequalLengths
	}
	for i, x := range a {
		out[i] = x ^ b[i]
	}
	return out, nil
}

var ErrUnequalLengths = errors.New("xor: byte arrays of unequal lengths")
