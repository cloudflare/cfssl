package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

var anything bool

// writer that writes to wr and sets 'anything' bool on any data
type fgtWriter struct {
	wr io.Writer
}

func (fgt *fgtWriter) Write(b []byte) (int, error) {
	if len(b) > 0 {
		anything = true
	}
	return fgt.wr.Write(b)
}

// fast go tester
func main() {
	// check for valid args
	if len(os.Args) < 2 {
		fmt.Println("usage: fgt <cmd> <args>")
		return
	}

	// prepare command
	cmd := exec.Command(os.Args[1], os.Args[2:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = &fgtWriter{
		wr: os.Stdout,
	}
	cmd.Stderr = &fgtWriter{
		wr: os.Stderr,
	}

	// run command, exit 1 on error
	err := cmd.Run()
	if err != nil && !strings.Contains(err.Error(), "exit status 1") {
		fmt.Printf("error running command: %s\n", err)
		os.Exit(1)
	}

	// exit 1 on no success
	if !cmd.ProcessState.Success() {
		os.Exit(1)
	}

	// exit 1 on anything being sent to stdout or stderr
	if anything {
		os.Exit(1)
	}
}
