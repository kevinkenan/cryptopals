package cryptopals

import (
	"math"
)

var (
	letterFreq = make(map[byte]float64)
)

func init() {
	letterFreq[byte(' ')] = .1300 // Guess
	letterFreq[byte('E')] = .1202
	letterFreq[byte('T')] = .0910
	letterFreq[byte('A')] = .0812
	letterFreq[byte('O')] = .0768
	letterFreq[byte('I')] = .0731
	letterFreq[byte('N')] = .0695
	letterFreq[byte('S')] = .0628
	letterFreq[byte('R')] = .0602
	letterFreq[byte('H')] = .0592
	letterFreq[byte('D')] = .0432
	letterFreq[byte('L')] = .0398
	letterFreq[byte('U')] = .0288
	letterFreq[byte('C')] = .0271
	letterFreq[byte('M')] = .0261
	letterFreq[byte('F')] = .0230
	letterFreq[byte('Y')] = .0211
	letterFreq[byte('W')] = .0209
	letterFreq[byte('G')] = .0203
	letterFreq[byte('P')] = .0182
	letterFreq[byte('B')] = .0149
	letterFreq[byte('V')] = .0111
	letterFreq[byte('K')] = .0069
	letterFreq[byte('X')] = .0017
	letterFreq[byte('Q')] = .0011
	letterFreq[byte('J')] = .0010
	letterFreq[byte('Z')] = .0007
}

// ScoreText returns a score that represents the difference between the letter
// frequency in the candidate text and the frequency of typical english text.
// Small scores mean a smaller average difference, so the smallest score is
// likely actual english. A score of zero would mean that frequency of text in
// the candidate exactly matches the standard frequency.
func ScoreText(candidate []byte) float64 {
	counts := make(map[byte]int)

	// Count the number of times each letter appears in candidate
	for _, b := range candidate {
		if 0x60 < b && b < 0x7B {
			// Count uppercase characters as lowercase
			counts[b-0x20] = counts[b-0x20] + 1
		} else {
			// Count lower case letters
			counts[b] = counts[b] + 1
		}
	}

	// Compute the difference between the standard letter frequency and the
	// frequency of letters from the candidate text.
	size := len(candidate)
	diff := 0.0
	for k, v := range counts {
		diff += math.Abs(letterFreq[k] - float64(v)/float64(size))
	}

	// Return the average of the differences.
	avgDiff := diff / float64(size)
	return avgDiff
}

// A utility type to make it easy to work with ScoredText. Implements
// sort.Interface.
type ScoredTextList []ScoredText

type ScoredText struct {
	Text  string
	Score float64
	Key   string
}

// Functions to implement sort.Interface
func (s ScoredTextList) Len() int           { return len(s) }
func (s ScoredTextList) Less(i, j int) bool { return s[i].Score < s[j].Score }
func (s ScoredTextList) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
