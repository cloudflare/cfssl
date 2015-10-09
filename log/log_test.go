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

	// test 1: outputf correctly prints string
	if !strings.Contains(buf.String(), string1) {
		t.Fail()
	}

	(*bytes.Buffer).Reset(buf)
	outputf(LevelDebug-1, string1, nil)

	// test 2: outputf will not print if level is below a range
	if buf.String() != "" {
		t.Fail()
	}
	return
}

func TestOutput(t *testing.T) {
	buf := new(bytes.Buffer)

	log.SetOutput(buf)
	output(LevelDebug, nil)

	// test 1: outputf correctly prints string with proper Debug prefix
	if !strings.Contains(buf.String(), levelPrefix[LevelDebug]) {
		t.Fail()
	}

	(*bytes.Buffer).Reset(buf)
	output(LevelDebug-1, nil)

	// test 2: outputf will not print if level is below a range
	if buf.String() != "" {
		t.Fail()
	}
	return
}

func TestCriticalf(t *testing.T) {
	const string1 = "asdf123"
	buf := new(bytes.Buffer)
	log.SetOutput(buf)
	Criticalf(string1, nil)

	// test 1: outputf correctly prints string
	// should never fail because critical > debug
	if !strings.Contains(buf.String(), string1) {
		t.Fail()
	}
	return
}

func TestCritical(t *testing.T) {
	const string1 = "asdf123"
	buf := new(bytes.Buffer)
	log.SetOutput(buf)
	Critical(nil)

	// test 1: outputf correctly prints string
	if !strings.Contains(buf.String(), levelPrefix[LevelCritical]) {
		t.Fail()
	}
	return
}

func TestWarningf(t *testing.T) {
	const string1 = "asdf123"
	buf := new(bytes.Buffer)
	log.SetOutput(buf)
	Warningf(string1, nil)

	// test 1: outputf correctly prints string
	// should never fail because fatal critical > debug
	if !strings.Contains(buf.String(), string1) {
		t.Fail()
	}
	return
}

func TestWarning(t *testing.T) {
	const string1 = "asdf123"
	buf := new(bytes.Buffer)
	log.SetOutput(buf)
	Warning(nil)

	// test 1: outputf correctly prints string
	if !strings.Contains(buf.String(), levelPrefix[LevelWarning]) {
		t.Fail()
	}
	return
}

func TestInfof(t *testing.T) {
	const string1 = "asdf123"
	buf := new(bytes.Buffer)
	log.SetOutput(buf)
	Infof(string1, nil)

	// test 1: outputf correctly prints string
	// should never fail because fatal info > debug
	if !strings.Contains(buf.String(), string1) {
		t.Fail()
	}
	return
}

func TestInfo(t *testing.T) {
	const string1 = "asdf123"
	buf := new(bytes.Buffer)
	log.SetOutput(buf)
	Info(nil)

	// test 1: outputf correctly prints string
	if !strings.Contains(buf.String(), levelPrefix[LevelInfo]) {
		t.Fail()
	}
	return
}

func TestDebugf(t *testing.T) {
	const string1 = "asdf123"
	buf := new(bytes.Buffer)
	log.SetOutput(buf)
	Debugf(string1, nil)

	// test 1: outputf correctly prints string
	// should never fail because fatal debug >= debug
	if !strings.Contains(buf.String(), string1) {
		t.Fail()
	}
	return
}

func TestDebug(t *testing.T) {
	const string1 = "asdf123"
	buf := new(bytes.Buffer)
	log.SetOutput(buf)
	Debug(nil)

	// test 1: outputf correctly prints string
	if !strings.Contains(buf.String(), levelPrefix[LevelDebug]) {
		t.Fail()
	}
	return

}
