package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	// CLI parsing
	runAll := flag.Bool("all", false, "run all challenges")
	setCmd := flag.Int("set", 0, "run a challenge from this set or all challenges from this set if --challenge is not also specified")
	chlCmd := flag.Int("challenge", 0, "run this challenge from the set")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "go run %s [--all|--set n (--challenge m)]:\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	// No flags set
	if !*runAll && *setCmd == 0 && *chlCmd == 0 {
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
	sets := make([][]func(), 8)
	set1 := []func(){
		s1c1,
		s1c2,
		s1c3,
		s1c4,
		s1c5,
		s1c6,
		s1c7,
		s1c8,
	}

	sets[0] = set1

	// Execute the challenges specified on the command line.
	if *runAll {
		for _, s := range sets {
			for _, c := range s {
				c()
			}
		}
	} else {
		theSet := sets[*setCmd-1]
		if *chlCmd == 0 {
			for _, c := range theSet {
				c()
			}
		} else {
			sets[*setCmd-1][*chlCmd-1]()
		}
	}
}
