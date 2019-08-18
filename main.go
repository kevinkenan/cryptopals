package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	// CLI parsing
	runAll := flag.Bool("all", false, "run all challenges")
	setCmd := flag.Int("set", 0, "run all the challenges from this set")
	chlCmd := flag.Int("challenge", 0, "run just this challenge")

	flag.Usage = func() {
		_, _ = fmt.Fprintf(os.Stderr, "%s [--all | --set n | --challenge m]:\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	// No flags set
	if len(os.Args) == 0 {
		fmt.Println(os.Args)
		flag.Usage()
		os.Exit(1)
	}

	// Flags: --all and either or both of --set and --challenge
	if *runAll && (*setCmd != 0 || *chlCmd != 0) {
		fmt.Println("You may not use --all along with other flags")
		os.Exit(1)
	}

	// Each challenge is solved in a function and we manage those functions in
	// a slice of func slices.
	set1 := []func(){s1c1, s1c2, s1c3, s1c4, s1c5, s1c6, s1c7, s1c8}
	set2 := []func(){s2c9, s2c10, s2c11, s2c12, s2c13, s2c14, s2c15, s2c16}
	set3 := []func(){s3c17, s3c18, s3c19, s3c20, s3c21, s3c22, s3c23, s3c24}
	set4 := []func(){s4c25, s4c26}
	sets := [][]func(){set1, set2, set3, set4}

	// Execute the challenges specified on the command line. The default go
	// command line parsing library is rather pathetic, but I don't want code
	// something more elaborate or use a third party package so this will have
	// to suffice.
	if *runAll {
		for _, s := range sets {
			for _, c := range s {
				c()
			}
		}
	} else if *setCmd != 0 {
		if *setCmd > len(sets) {
			fmt.Println("set must be between 1 and", len(sets))
			os.Exit(1)
		}
		theSet := sets[*setCmd-1]
		for _, c := range theSet {
			c()
		}
	} else if *chlCmd != 0 {
		setStart := 0
		for i, s := range sets {
			if *chlCmd <= setStart+len(sets[i]) {
				s[*chlCmd-1-setStart]()
				break
			}
			setStart = setStart + len(sets[i])
		}
	}
}
