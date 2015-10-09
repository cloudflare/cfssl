package log

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// helper to save stdout to a string
func stdoutToStr(format string) string {
	old := os.Stdout // keep backup of  the real stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	outputf(LevelDebug, format, nil)

	outC := make(chan string)
	// copy the output in a separate goroutine so printing can't block indefinitely
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		outC <- buf.String()
	}()

	// back to normal state
	w.Close()
	os.Stdout = old // restoring the real stdout
	out := <-outC

	return out
}

func TestOutputf(t *testing.T) {
	out := stdoutToStr("asdf")

	//test with invalid inputs.
	if strings.Contains(out, "test") {
		t.Fatal()
	}

	return
}
