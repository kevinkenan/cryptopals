package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"sort"

	// "io/ioutil"
	"crypto/rand"
	"os"

	cryptopals "github.com/kevinkenan/cryptopals/utils"
)

func s3c19() {
	fmt.Println("Set 3, Challenge 19")
	var err error
	var guessedKey []byte

	// Read in test data
	f, err := os.Open("s3c19data.txt")
	if err != nil {
		fmt.Print("Error:", err)
	}
	defer f.Close()

	var plaintexts [][]byte

	// Base64 decode the file of plaintexts
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		// Load a line into the plaintext slice.
		p, err := base64.StdEncoding.DecodeString(scanner.Text())
		if err != nil {
			fmt.Println(err)
		}
		plaintexts = append(plaintexts, p)
		// fmt.Println(string(p))
	}

	nonce := make([]byte, 8)

	// Generate a random key.
	key := make([]byte, 16)
	_, err = rand.Read(key)
	if err != nil {
		cryptopals.PrintError(err)
		return
	}

	longestCiphertext := 0

	// Encrypt the plaintexts.
	ciphertexts := make([][]byte, len(plaintexts))
	for i, p := range plaintexts {
		c, err := cryptopals.ApplyAESwithCTR(p, key, nonce, 0)
		if err != nil {
			cryptopals.PrintError(err)
			return
		}
		ciphertexts[i] = c
		if len(c) > longestCiphertext {
			longestCiphertext = len(c)
		}
	}

	guessedKey = make([]byte, longestCiphertext)

	var counts c19byteCountList

	// Looking at just the first letters of each ciphertext.
	for _, c := range ciphertexts {
		counts.Add(c[0])
	}

	// Sort so the most frequent letters are at the beginning of the slice.
	sort.Stable(sort.Reverse(counts))

	// The most common first letter of a word is A. So we'll guess that the
	// most frequent letter in our ciphertext is an A.
	guessedKey[0] = counts[0].value ^ 'A'

	// Turns out that is a good guess as it returns a bunch of English
	// letters. Uncomment the lines below to see.
	// for _, c := range ciphertexts {
	// 	fmt.Println(string(c[0] ^ guessedKey[0]))
	// }

	// The first letter of the first text is 'I'. Let's guess that the second
	// letter is a space.
	guessedKey[1] = ciphertexts[0][1] ^ ' '

	// That guess looks good. Uncomment to see.
	// for _, c := range ciphertexts {
	// 	g, _ := cryptopals.XorByteArrays(c[:2], guessedKey[:2])
	// 	fmt.Println(string(g))
	// }

	// Lines 5 and 6 are "Or". Let's assume those are words and would be
	// followed by a space.
	guessedKey[2] = ciphertexts[5][2] ^ ' '

	// That guess looks good. Uncomment to see.
	// for _, c := range ciphertexts {
	// 	g, _ := cryptopals.XorByteArrays(c[:3], guessedKey[:3])
	// 	fmt.Println(string(g))
	// }

	// Line 8 is "And". Let's again assume that it's the word and the
	// next character is a space.
	guessedKey[3] = ciphertexts[8][3] ^ ' '

	// That guess looks good. Uncomment to see.
	// for _, c := range ciphertexts {
	// 	g, _ := cryptopals.XorByteArrays(c[:4], guessedKey[:4])
	// 	fmt.Println(string(g))
	// }

	// Line 2 is "From". Let's again assume that it's the word and the
	// next character is a space.
	guessedKey[4] = ciphertexts[2][4] ^ ' '

	// That guess looks good. Uncomment to see.
	// for _, c := range ciphertexts {
	// 	g, _ := cryptopals.XorByteArrays(c[:5], guessedKey[:5])
	// 	fmt.Println(string(g))
	// }

	// Line 1 is "Comin". Let's guess that the next letter is a 'g'.
	guessedKey[5] = ciphertexts[1][5] ^ 'g'

	// That guess looks good. Uncomment to see.
	// for _, c := range ciphertexts {
	// 	g, _ := cryptopals.XorByteArrays(c[:6], guessedKey[:6])
	// 	fmt.Println(string(g))
	// }

	// Line 1 is "Coming". Let's guess that the next letter is a ' '.
	guessedKey[6] = ciphertexts[1][6] ^ ' '

	// That guess looks good. Uncomment to see.
	// for _, c := range ciphertexts {
	// 	g, _ := cryptopals.XorByteArrays(c[:7], guessedKey[:7])
	// 	fmt.Println(string(g))
	// }

	// Line 3 is "Eightee". Let's guess that the next letter is an 'n'.
	guessedKey[7] = ciphertexts[3][7] ^ 'n'

	// That guess looks good. Uncomment to see.
	// for _, c := range ciphertexts {
	// 	g, _ := cryptopals.XorByteArrays(c[:8], guessedKey[:8])
	// 	fmt.Println(string(g))
	// }

	// Line 15 ends with "terrib". Let's guess that the next letter is an 'l'.
	guessedKey[8] = ciphertexts[15][8] ^ 'l'

	// That guess looks good. Uncomment to see.
	// for _, c := range ciphertexts {
	// 	g, _ := cryptopals.XorByteArrays(c[:9], guessedKey[:9])
	// 	fmt.Println(string(g))
	// }

	// Line 15 ends with "terribl". Let's guess that the next letter is an 'e'.
	guessedKey[9] = ciphertexts[15][9] ^ 'e'

	// That guess looks good. Uncomment to see.
	// for _, c := range ciphertexts {
	// 	g, _ := cryptopals.XorByteArrays(c[:10], guessedKey[:10])
	// 	fmt.Println(string(g))
	// }

	// Line 1 is "Coming wit". Let's guess that the next letter is an 'h'.
	guessedKey[10] = ciphertexts[1][10] ^ 'h'

	// That guess looks good. Uncomment to see.
	// for _, c := range ciphertexts {
	// 	g, _ := cryptopals.XorByteArrays(c[:11], guessedKey[:11])
	// 	fmt.Println(string(g))
	// }

	// Line 9 is "...mockin". Let's guess that the next letter is an 'g'.
	guessedKey[11] = ciphertexts[9][11] ^ 'g'

	// That guess looks good. Uncomment to see.
	// for _, c := range ciphertexts {
	// 	g, _ := cryptopals.XorByteArrays(c[:12], guessedKey[:12])
	// 	fmt.Println(string(g))
	// }

	// Line 3 is "Eighteen-c". Let's guess that the next letters are 'entury '.
	guessedKey[12] = ciphertexts[3][12] ^ 'e'
	guessedKey[13] = ciphertexts[3][13] ^ 'n'
	guessedKey[14] = ciphertexts[3][14] ^ 't'
	guessedKey[15] = ciphertexts[3][15] ^ 'u'
	guessedKey[16] = ciphertexts[3][16] ^ 'r'
	guessedKey[17] = ciphertexts[3][17] ^ 'y'
	guessedKey[18] = ciphertexts[3][18] ^ ' '

	// That guess looks good. Uncomment to see.
	// for _, c := range ciphertexts {
	// 	g, _ := cryptopals.XorByteStream(c, guessedKey[:19])
	// 	fmt.Println(string(g))
	// }

	// Line 21 is "...beau". Let's guess that the next letters are 'tiful'.
	guessedKey[19] = ciphertexts[21][19] ^ 't'
	guessedKey[20] = ciphertexts[21][20] ^ 'i'
	guessedKey[21] = ciphertexts[21][21] ^ 'f'
	guessedKey[22] = ciphertexts[21][22] ^ 'u'
	guessedKey[23] = ciphertexts[21][23] ^ 'l'

	// That guess looks good. Uncomment to see.
	// for _, c := range ciphertexts {
	// 	g, _ := cryptopals.XorByteStream(c, guessedKey[:24])
	// 	fmt.Println(string(g))
	// }

	// Line 5 is "...meaningless wo". Let's guess that the next letters are 'rds '.
	guessedKey[24] = ciphertexts[5][24] ^ 'r'
	guessedKey[25] = ciphertexts[5][25] ^ 'd'
	guessedKey[26] = ciphertexts[5][26] ^ 's'

	// That guess looks good. Uncomment to see.
	// for _, c := range ciphertexts {
	// 	g, _ := cryptopals.XorByteStream(c, guessedKey[:27])
	// 	fmt.Println(string(g))
	// }

	// Line 0 is "I have met them at close of". Let's guess that the next letters are ' day'.
	guessedKey[27] = ciphertexts[0][27] ^ ' '
	guessedKey[28] = ciphertexts[0][28] ^ 'd'
	guessedKey[29] = ciphertexts[0][29] ^ 'a'
	guessedKey[30] = ciphertexts[0][30] ^ 'y'

	// That guess looks good. Uncomment to see.
	// for _, c := range ciphertexts {
	// 	g, _ := cryptopals.XorByteStream(c, guessedKey[:31])
	// 	fmt.Println(string(g))
	// }

	// Line 25 is "...his helper and frien". Let's guess that the next letter is 'd'.
	guessedKey[31] = ciphertexts[25][31] ^ 'd'

	// That guess looks good. Uncomment to see.
	// for _, c := range ciphertexts {
	// 	g, _ := cryptopals.XorByteStream(c, guessedKey[:32])
	// 	fmt.Println(string(g))
	// }

	// Line 27 is "...in the en". Let's guess that the next letter is 'd'.
	guessedKey[32] = ciphertexts[27][32] ^ 'd'

	// That guess looks good. Uncomment to see.
	// for _, c := range ciphertexts {
	// 	g, _ := cryptopals.XorByteStream(c, guessedKey[:33])
	// 	fmt.Println(string(g))
	// }

	// Line 4 is "...with a nod of the h". Let's guess that the next letters are 'ead'.
	guessedKey[33] = ciphertexts[4][33] ^ 'e'
	guessedKey[34] = ciphertexts[4][34] ^ 'a'
	guessedKey[35] = ciphertexts[4][35] ^ 'd'

	// That guess looks good. Uncomment to see.
	// for _, c := range ciphertexts {
	// 	g, _ := cryptopals.XorByteStream(c, guessedKey[:36])
	// 	fmt.Println(string(g))
	// }

	// Line 37 is "...in his tur". Let's guess that the next letter is 'n'.
	guessedKey[36] = ciphertexts[37][36] ^ 'n'

	// That guess looks good. Uncomment to see.
	// for _, c := range ciphertexts {
	// 	g, _ := cryptopals.XorByteStream(c, guessedKey[:37])
	// 	fmt.Println(string(g))
	// }

	// There's just one byte left to guess, and it's on line 37 which reads
	// "He, too, has been changed in his turn". Given the context, I'm
	// guessing that the next character is a ','.
	guessedKey[37] = ciphertexts[37][37] ^ ','

	// That guess looks good. Uncomment to see.
	// for _, c := range ciphertexts {
	// 	g, _ := cryptopals.XorByteStream(c, guessedKey[:38])
	// 	fmt.Println(string(g))
	// }

	success := true
	for i, c := range ciphertexts {
		g, _ := cryptopals.XorByteStream(c, guessedKey)
		if !bytes.Equal(g, plaintexts[i]) {
			fmt.Println(string(plaintexts[i]))
			fmt.Println(string(g))
			success = false
			break
		}
	}

	if success {
		cryptopals.PrintSuccess("")
	} else {
		cryptopals.PrintFailure("")
	}
}

// Probably a bit overkill, but wanted to write the Add function.
// Anyways, this type is only used to make the first guess.
type c19byteCountList []c19byteCount

type c19byteCount struct {
	value byte
	count int
}

// The first 3 implment the sort interface
func (c c19byteCountList) Len() int           { return len(c) }
func (c c19byteCountList) Less(i, j int) bool { return c[i].count < c[j].count }
func (c c19byteCountList) Swap(i, j int)      { c[i], c[j] = c[j], c[i] }
func (c *c19byteCountList) Add(b byte) c19byteCountList {
	// fmt.Println("----")
	foundByte := false
	for i, bc := range *c {
		// fmt.Println("> ", bc)
		if bc.value == b {
			newc := bc.count + 1
			(*c)[i].count = newc
			foundByte = true
			// fmt.Println("Update", b, (*c)[i].count, bc.count)
			break
		}
	}
	if !foundByte {
		*c = append(*c, c19byteCount{value: b, count: 1})
		// fmt.Println("HERE", *c[len(*c)-1].count)
		// fmt.Println("New", b, (*c)[0].count)
	}
	return *c
}
