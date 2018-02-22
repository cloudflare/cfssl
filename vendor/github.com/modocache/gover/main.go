/*
Usage: gover [root] [out]

Collects all .coverprofile files rooted in [root] and concatenantes them
into a single file at [out].

[out] is not concatenated onto itself, even if it is in [root] and has a
.coverprofile extension.

[root] defaults to the current directory, [out] to 'gover.coverprofile'.

For more details, consult the README: https://github.com/modocache/gover
*/
package main

import (
	"flag"
	"fmt"
	"github.com/modocache/gover/gover"
	"log"
	"os"
)

const (
	defaultOut = "gover.coverprofile"
	usage      = "Usage: gover [root] [out]\n\nCollects all .coverprofile files rooted in [root] and concatenantes them into a single file at [out].\n[root] defaults to the current directory, [out] to 'gover.coverprofile'.\n\nFor more details see: https://github.com/modocache/gover"
)

func defaultRoot() string {
	root, err := os.Getwd()
	if err != nil {
		log.Fatal("gover: Could not get current working directory")
	}
	return root
}

func parseArgs(args []string) (string, string) {
	var root, out string
	if len(args) == 0 {
		root, out = defaultRoot(), defaultOut
	} else if len(args) == 1 {
		root, out = args[0], defaultOut
	} else {
		root, out = args[0], args[1]
	}

	return root, out
}

func main() {
	flag.Parse()
	args := flag.Args()
	if len(args) > 2 {
		fmt.Println(usage)
		os.Exit(1)
	}

	root, out := parseArgs(args)
	gover.Gover(root, out)
}
