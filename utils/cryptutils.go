package cryptopals

import (
	// "bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/mitchellh/colorstring"
	"math"
	"math/bits"
	"sort"
)

func stopTheComplainingAboutFmt() {
	fmt.Println("")
}

func PrintSuccess(s string) {
	if len(s) != 0 {
		colorstring.Printf("  [bold][green]Success[reset]: %#v\n", s)
	} else {
		colorstring.Println("  [bold][green]Success")
	}
}

func PrintFailure(s string) {
	if len(s) != 0 {
		colorstring.Printf("  [bold][red]Failure[reset]: %#v\n", s)
	} else {
		colorstring.Println("  [bold][red]Failure")
	}
}

func PrintError(err error) {
	if err != nil {
		colorstring.Printf("  [bold][red]ERROR[reset]: %#s\n", err)
	} else {
		colorstring.Println("  [bold][red]ERROR")
	}
}

func StripPadding(text []byte, blockSize int) ([]byte, error) {
	if len(text)%blockSize != 0 {
		return nil, errors.New("Input not a multiple of blockSize")
	}

	lastByte := int(text[len(text)-1])
	if lastByte == 0 || lastByte > 16 {
		return nil, errors.New("Invalid padding")
	}

	blockCount := len(text) / blockSize
	lastBlock := text[(blockCount-1)*blockSize : blockCount*blockSize]
	for i := blockSize - lastByte; i < 16; i++ {
		if int(lastBlock[i]) != lastByte {
			return nil, errors.New("Wrong number of padding bytes")
		}
	}

	return text[:len(text)-lastByte], nil
}

func PrintBlocks(b []byte, blockSize int) {
	blockCount := len(b) / blockSize
	for i := 0; i < blockCount; i++ {
		fmt.Println(b[i*blockSize : (i+1)*blockSize])
	}
	if len(b) > blockSize*blockCount {
		fmt.Println(b[blockCount*blockSize:])
	}
	fmt.Println("")
}

func PrintHexBlocks(b []byte, blockSize int) {
	blockCount := len(b) / blockSize
	for i := 0; i < blockCount; i++ {
		s := b[i*blockSize : (i+1)*blockSize]
		fmt.Printf("%03v: [", i)
		for j := 0; j < blockSize-1; j++ {
			fmt.Printf("%02x ", s[j])
		}
		fmt.Printf("%02x]\n", s[blockSize-1])
	}
	// Print last block
	if len(b) > blockSize*blockCount {
		s := b[blockCount*blockSize:]
		fmt.Printf("%03v: [", blockCount)
		for j := 0; j < len(s)-1; j++ {
			fmt.Printf("%02x ", s[j])
		}
		fmt.Printf("%02x]\n", s[len(s)-1])
		// fmt.Printf(b[blockCount*blockSize:])
	}
	fmt.Println("")
}

func GetBlock(b []byte, c int, blockSize int) []byte {
	// Zero based.
	return b[(c)*blockSize : (c+1)*blockSize]
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
	cleartext = cleartext[0 : len(cleartext)-int(p)]

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
	if blockCount == 0 {
		return nil, errors.New("Invalid ciphertext")
	}
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

	// fmt.Println("cleartext")
	// PrintHexBlocks(cleartext, 16)

	unpaddedCleartext, err := StripPadding(cleartext, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	// fmt.Println("unpadded")
	// PrintHexBlocks(unpaddedCleartext, 16)

	return unpaddedCleartext, nil
}

// This function is used for both encryption and decryption.
func ApplyAESwithCTR(intext, key, nonce []byte, start uint64) ([]byte, error) {
	var err error
	outtext := make([]byte, len(intext))

	// Start the keystream which generates the key bytes.
	keystream := make(chan keyByte)
	go keystreamGen(nonce, key, start, keystream)

	// XOR each byte of intext with a byte from the keystream.
	for i, t := range intext {
		k := <-keystream
		if k.Err != nil {
			return nil, err
		}
		outtext[i] = t ^ k.Byte
	}

	return outtext, nil
}

func keystreamGen(nonce, key []byte, start uint64, c chan keyByte) {
	inc := start
	incBuf := make([]byte, 8)
	ctr := make([]byte, 16)

	for inc < math.MaxUint64 {
		// Build the ctr which is a concatenation of the nonce and the
		// incrementing inc.
		binary.LittleEndian.PutUint64(incBuf, inc)
		copy(ctr, nonce)
		copy(ctr[8:16], incBuf)

		// Generate a block of keystream bytes
		keystreamBlock, err := EncryptAESwithECB(ctr, key)
		if err != nil {
			c <- keyByte{0x00, err}
		}

		// Send the keystream bytes out the channel one at time.
		for i := 0; i < 16; i++ {
			c <- keyByte{keystreamBlock[i], nil}
		}

		// When we've used all the bytes in a keystream block, increment the
		// inc variable and continue with the loop to generate a new keystream
		// block.
		inc++
	}

	// We've used all the keystream bytes available with that nonce. Further
	// use is not advised.
	c <- keyByte{0x00, errors.New("Keystream exhausted")}
}

// This struct makes it easy to report on errors from the Go routine. It's not
// the most efficient way to watch for errors in a routine, but I didn't want
// to set up another channel for this challenge.
type keyByte struct {
	Byte byte
	Err  error
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
	key := make([]byte, ptxtLen)
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
		b := ciphertext[keyLen : 2*keyLen]
		c := ciphertext[2*keyLen : 3*keyLen]
		d := ciphertext[3*keyLen : 4*keyLen]

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

		dist := (float64(dist1) + float64(dist2) + float64(dist3)) / (3.0 * float64(keyLen))

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
	Score     float64
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

func XorByteStream(a, b []byte) ([]byte, error) {
	minSize := min(len(a), len(b))
	out := make([]byte, minSize)
	for i := 0; i < minSize; i++ {
		out[i] = a[i] ^ b[i]
	}

	return out, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Mersenne Twister (MT19937)

// Constants
const MT_w = uint32(32)
const MT_n = uint32(624)
const MT_m = uint32(397)
const MT_r = uint32(31)
const MT_a = uint32(0x9908B0DF)
const MT_u = uint32(11)
const MT_d = uint32(0xFFFFFFFF)
const MT_s = uint32(7)
const MT_b = uint32(0x9D2C5680)
const MT_t = uint32(15)
const MT_c = uint32(0xEFC60000)
const MT_l = uint32(18)
const MT_f = uint32(1812433253)
const lowerMask = uint32((1 << MT_r) - 1) // 0x7fffffff
const upperMask = uint32(^lowerMask)      // 0x80000000

type MT19937 struct {
	initialized bool
	Seed        uint32
	Index       uint32   // the Index of the next random number to be returned
	state       []uint32 // the current set of random numbers
	reseed      bool
}

func RandomGen(seed uint32, ch chan uint32) {
	// Initialization
	var mt MT19937
	mt.init(seed)

	for {
		ch <- mt.generate()
	}
}

// Initialize the state.
func (mt *MT19937) init(seed uint32) {

	mt.Seed = seed
	state := make([]uint32, MT_n)
	state[0] = seed
	for i := uint32(1); i < MT_n; i++ {
		state[i] = (MT_f*(state[i-1]^(state[i-1]>>(MT_w-2))) + i)
	}
	mt.state = state

	// Point the Index to the last element of the state so that
	// the twist is called before returning any values.
	mt.Index = MT_n

	// Mark it as initialized.
	mt.initialized = true
}

// Return the next random number.
func (mt *MT19937) generate() uint32 {
	// Twist if it's time
	if mt.Index == MT_n {
		_, err := mt.twist()
		if err != nil {
			fmt.Println("ERROR:", err)
			return 0
		}
	}

	// Temper the output
	y := mt.state[mt.Index]
	y = y ^ ((y >> MT_u) & MT_d)
	y = y ^ ((y << MT_s) & MT_b)
	y = y ^ ((y << MT_t) & MT_c)
	y = y ^ (y >> MT_l)
	mt.Index++

	return y
}

// Populate the state array with a new set of values.
func (mt *MT19937) twist() (uint32, error) {
	if !mt.initialized {
		return 0, errors.New("Generator was not seeded")
	}

	for i := uint32(0); i < MT_n; i++ {
		x := (mt.state[i] & upperMask) + (mt.state[(i+1)%MT_n] & lowerMask)
		xA := x >> 1
		if (x % 2) != 0 { // lowest bit of x is 1
			xA = xA ^ MT_a
		}
		mt.state[i] = mt.state[(i+MT_m)%MT_n] ^ xA
	}
	mt.Index = 0

	return mt.Index, nil
}

// Allows the state to be set directly rather than generating it from a seed.
func HackedRandomGen(st []uint32, ch chan uint32) {
	var mt MT19937
	mt.state = st
	mt.Index = MT_n
	mt.initialized = true

	for {
		ch <- mt.generate()
	}
}

// MT implementation that supports reseeding.
func RandomGenReseed(seed uint32, out, reseed chan uint32) *MT19937 {
	// Initialization
	var mt MT19937
	mt.init(seed)
	y := mt.generate()

	go func() {
		for {
			select {
			case out <- y:
				y = mt.generate()
			case seed = <-reseed:
				mt.init(seed)
				y = mt.generate()
			}
		}
	}()

	return &mt
}

// Using MT as a stream cipher that also supports reseeding.
func MTStreamCipher(seed uint32, reseed chan uint32, out chan byte) {
	var mt MT19937
	mt.init(seed)
	y := mt.generate()
	c := 0
	b := byte((y >> uint32(c*8)) & 0x000000FF)

	go func() {
		for {
			select {
			case out <- b:
				c += 1
				if c > 3 {
					y = mt.generate()
					c = 0
				}
				b = byte((y >> uint32(c*8)) & 0x000000FF)
			case seed = <-reseed:
				mt.init(seed)
				y = mt.generate()
				c = 0
				b = byte((y >> uint32(c*8)) & 0x000000FF)
			}
		}
	}()
}
