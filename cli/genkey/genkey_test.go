package genkey

import (
	"encoding/json"
	"errors"
	"github.com/cloudflare/cfssl/certinfo"
	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/config"
	"io/ioutil"
	"math"
	"os"
	"testing"
	"time"
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
	return ioutil.ReadAll(pipe.r)
}

func checkResponse(out []byte) (map[string]interface{}, error) {
	var response map[string]interface{}
	if err := json.Unmarshal(out, &response); err != nil {
		return nil, err
	}

	if response["key"] == nil {
		return nil, errors.New("no key is outputted")
	}

	if response["csr"] == nil {
		return nil, errors.New("no csr is outputted")
	}

	return response, nil
}

func TestGenkey(t *testing.T) {
	var pipe *stdoutRedirect
	var out []byte
	var err error

	if pipe, err = newStdoutRedirect(); err != nil {
		t.Fatal("Could not create stdout pipe; cannot run test.", err)
	}
	if err := genkeyMain([]string{"testdata/csr.json"}, cli.Config{}); err != nil {
		t.Fatal(err)
	}
	if out, err = pipe.readAll(); err != nil {
		t.Fatal("Couldn't read from stdout", err)
	}
	if _, err := checkResponse(out); err != nil {
		t.Fatal("Format on stdout is unexpected", err)
	}

	if pipe, err = newStdoutRedirect(); err != nil {
		t.Fatal("Could not create stdout pipe; cannot run test.", err)
	}
	if err := genkeyMain([]string{"testdata/csr.json"}, cli.Config{IsCA: true}); err != nil {
		t.Fatal(err)
	}
	if out, err = pipe.readAll(); err != nil {
		t.Fatal("Couldn't read from stdout", err)
	}
	if _, err := checkResponse(out); err != nil {
		t.Fatal("Format on stdout is unexpected", err)
	}
}

func TestGenkeyWithConfigLoading(t *testing.T) {
	var pipe *stdoutRedirect
	var out []byte
	var err error

	if pipe, err = newStdoutRedirect(); err != nil {
		t.Fatal("Could not create stdout pipe; cannot run test.", err)
	}

	c := cli.Config{
		// note: despite IsCA being re-specified in ConfigFile, it also needs to be manually set in config
		IsCA:       true,
		ConfigFile: "../../testdata/good_config_ca.json",
	}

	// loading the config is done in the entrypoint of the program, we have to fill c.CFG manually here
	c.CFG, err = config.LoadFile(c.ConfigFile)
	if c.ConfigFile != "" && err != nil {
		t.Fatal("Failed to load config file:", err)
	}

	if err := genkeyMain([]string{"testdata/csr.json"}, c); err != nil {
		t.Fatal(err)
	}

	if out, err = pipe.readAll(); err != nil {
		t.Fatal("Couldn't read from stdout", err)
	}
	response, err := checkResponse(out)
	if err != nil {
		t.Fatal("Format on stdout is unexpected", err)
	}

	cert := []byte(response["cert"].(string))

	parsedCert, err := certinfo.ParseCertificatePEM(cert)
	if err != nil {
		t.Fatal("Couldn't parse the produced cert", err)
	}

	HoursInAYear := float64(8766) // 365.25 * 24
	expiryHoursInConfig := c.CFG.Signing.Default.Expiry.Hours()
	expiryYearsInConfig := int(math.Ceil(expiryHoursInConfig / HoursInAYear))
	certExpiryInYears := parsedCert.NotAfter.Year() - time.Now().Year()

	if certExpiryInYears != expiryYearsInConfig {
		t.Fatal("Expiry specified in Config file is", expiryYearsInConfig, "but cert has expiry", certExpiryInYears)
	}
}
