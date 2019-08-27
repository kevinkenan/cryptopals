package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	cryptopals "github.com/kevinkenan/cryptopals/utils"
	"io/ioutil"
	"net/http"
	"time"
)

func s4c31() {
	fmt.Println("Set 4, Challenge 31")
	hmacTimingBreak(50, 1, 1)
}

// hmacTimingBreak attempts to break a SHA-1 HMAC using an artificial time
// delay. The server is queried for each byte in each position a number of times
// equal to the maxCount. As maxCount increases, the influence of random
// variations in timing decreases, but greater values of maxCount take longer to
// compute. The maxRounds value limits the number of times the trials are run,
// but it is applied only when the total amount of time isn't significant enough
// to conclude that we've found the right byte.
func hmacTimingBreak(delay, maxCount, maxRounds int) {
	http.DefaultTransport.(*http.Transport).MaxIdleConnsPerHost = 500

	// Generate a random HMAC key.
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		cryptopals.PrintError(err)
		return
	}

	srv := startC31WebServer(key, delay)

	file := "password"
	hf := cryptopals.NewHmacSha1(key)
	mac := hf([]byte(file))

	fmt.Println("  Delay:", delay, "milliseconds")
	fmt.Println("  Goal: ", hex.EncodeToString(mac[:]))

	hash := [20]byte{}

	// We brute force each of the 20 bytes in the SHA-1 hash.
	for i := 0; i < 20; i++ {
		times := make(map[byte]int64)
		round := 0

	ROUND:
		// Each round consists of 4 batches, and each batch concurrently checks
		// 64 of the 256 possible bytes for the value at position i in the hash.
		for k := 0; k < 4; k++ {
			ch := make(chan c31Timing, 64)

			// Kick off 64 goroutines to check a batch of 64 possible bytes.
			for j := 0; j < 64; j++ {
				go checkByte(byte(j+(k*64)), i, file, hash, ch, maxCount)
			}

			// Read the timing information from each goroutine.
			for j := 0; j < 64; j++ {
				select {
				case c := <-ch:
					times[c.b] += c.d
				}
			}

			close(ch)
		}

		// The byte that took the longest should be the correct byte. This is
		// because the correct byte would have checked the next byte before
		// throwing an error.
		longest, plongest := int64(0), int64(0)
		for b, t := range times {
			if t > longest {
				plongest = longest
				longest = t
				hash[i] = b
			}
		}

		// If the longest isn't significantly longer than the next longest, do
		// another round of checks.
		//println(i, (longest-plongest)/1000000, fmt.Sprintf("%02x", hash[i]))
		if longest-plongest < 5*1000000 && round < maxRounds {
			round += 1
			goto ROUND
		}

		fmt.Printf("  Found: %v\n", hex.EncodeToString(hash[:]))
	}

	// Check to see if we have the correct signature.
	h := hex.EncodeToString(hash[:])
	resp, err := http.Get("http://localhost:8080/test?file=" + file + "&signature=" + h)
	if err != nil {
		cryptopals.PrintError(err)
		return
	}

	if resp.StatusCode == 200 {
		cryptopals.PrintSuccess("")
	} else {
		cryptopals.PrintFailure("")
		body, _ := ioutil.ReadAll(resp.Body)
		fmt.Printf("  %s: %s", resp.Status, body)
	}

	_ = srv.Shutdown(context.Background())
}

func startC31WebServer(key []byte, delay int) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/test", c31MakeHandler(key, delay))
	mux.HandleFunc("/hi", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("Hello"))
	})

	srv := &http.Server{Addr: ":8080", Handler: mux}

	go func() {
		_ = srv.ListenAndServe()
	}()

	return srv
}

type c31Timing struct {
	b byte
	d int64
}

func checkByte(b byte, pos int, file string, hash [20]byte, ch chan c31Timing, count int) {
	hash[pos] = b
	var t int64

	for k := 0; k < count; k++ {
		s := time.Now()
		queryWebServer(hash, file)
		d := time.Since(s)
		t += d.Nanoseconds()
	}

	ch <- c31Timing{b: b, d: t}
}

func queryWebServer(hash [20]byte, file string) []byte {
	h := hex.EncodeToString(hash[:])

	resp, err := http.Get("http://localhost:8080/test?file=" + file + "&signature=" + h)
	if err != nil {
		cryptopals.PrintError(err)
		return nil
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	return body
}

func c31MakeHandler(key []byte, delay int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f := q.Get("file")
		s := q.Get("signature")

		hf := cryptopals.NewHmacSha1(key)
		mac := hf([]byte(f))

		sb, err := hex.DecodeString(s)
		if err != nil {
			http.Error(w, fmt.Sprintf("malformed signature: %s", s), http.StatusInternalServerError)
			return
		}

		if equal := insecureCompare(mac[:], sb, delay); !equal {
			http.Error(w, fmt.Sprintf("bad signature: %s", s), http.StatusInternalServerError)
			return
		}

		_, _ = fmt.Fprintf(w, "signature is correct %s\n", s)
	}
}

func insecureCompare(x, y []byte, delay int) bool {
	if len(x) != len(y) {
		return false
	}

	for i, b := range x {
		if b != y[i] {
			return false
		}

		// This artificial delay makes it a bit easier to launch a timing
		// attack.
		time.Sleep(time.Duration(delay) * time.Millisecond)
	}

	return true
}
