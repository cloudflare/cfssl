package gencsr

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/cloudflare/cfssl/cli"
)

const (
	testKeyFile    = "testdata/test-key.pem"
	testCAKeyFile  = "../testdata/ca-key.pem"
	testCACertFile = "../testdata/ca.pem"
)

type stdoutRedirect struct {
	r     *os.File
	w     *os.File
	saved *os.File
}

func newStdoutRedirect() (*stdoutRedirect, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}

	pipe := &stdoutRedirect{r, w, os.Stdout}
	os.Stdout = pipe.w
	return pipe, nil
}

func (pipe *stdoutRedirect) readAll() ([]byte, error) {
	pipe.w.Close()
	os.Stdout = pipe.saved
	return io.ReadAll(pipe.r)
}

func checkResponse(out []byte) error {
	var response map[string]interface{}
	if err := json.Unmarshal(out, &response); err != nil {
		return err
	}

	if response["key"] == nil {
		return errors.New("no key is outputted")
	}

	if response["csr"] == nil {
		return errors.New("no csr is outputted")
	}

	return nil
}

func TestGencsr(t *testing.T) {
	var pipe *stdoutRedirect
	var out []byte
	var err error

	if pipe, err = newStdoutRedirect(); err != nil {
		t.Fatal(err)
	}
	if err := gencsrMain([]string{"testdata/csr.json"}, cli.Config{KeyFile: testKeyFile}); err != nil {
		t.Fatal(err)
	}
	if out, err = pipe.readAll(); err != nil {
		t.Fatal(err)
	}
	if err := checkResponse(out); err != nil {
		t.Fatal(err)
	}
}

func TestGencsrFromCert(t *testing.T) {
	var pipe *stdoutRedirect
	var out []byte
	var err error

	if pipe, err = newStdoutRedirect(); err != nil {
		t.Fatal(err)
	}
	if err := gencsrMain([]string{}, cli.Config{KeyFile: testCAKeyFile, CertFile: testCACertFile}); err != nil {
		t.Fatal(err)
	}
	if out, err = pipe.readAll(); err != nil {
		t.Fatal(err)
	}
	if err := checkResponse(out); err != nil {
		t.Fatal(err)
	}
}

func TestGencsrError(t *testing.T) {
	if err := gencsrMain([]string{"testdata/csr.json"}, cli.Config{}); err == nil {
		t.Fatal("should have erred.")
	}
}
