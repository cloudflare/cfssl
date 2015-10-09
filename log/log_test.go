package log

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func TestOutputf(t *testing.T) {
	const string1 = "asdf123"
	buf := new(bytes.Buffer)

	log.SetOutput(buf)
	outputf(LevelDebug, string1, nil)
	line := buf.String()

	// if output contains original string, then test passes
	if !strings.Contains(line, string1) {
		t.Fail()
	}

	return
}
