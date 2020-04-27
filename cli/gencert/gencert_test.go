package gencert

import (
	"encoding/json"
	"fmt"
	"github.com/cloudflare/cfssl/certinfo"
	"github.com/cloudflare/cfssl/config"
	"io/ioutil"
	"errors"
	"math"
	"os"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/cli"
)

func TestGencertMain(t *testing.T) {

	c := cli.Config{
		IsCA: true,
	}

	err := gencertMain([]string{"../testdata/csr.json"}, c)
	if err != nil {
		t.Fatal(err)
	}

	c = cli.Config{
		IsCA:      true,
		CAKeyFile: "../testdata/ca-key.pem",
	}

	err = gencertMain([]string{"../testdata/csr.json"}, c)
	if err != nil {
		t.Fatal(err)
	}

	c = cli.Config{
		CAFile:    "../testdata/ca.pem",
		CAKeyFile: "../testdata/ca-key.pem",
	}

	err = gencertMain([]string{"../testdata/csr.json"}, c)
	if err != nil {
		t.Fatal(err)
	}

	c = cli.Config{
		RenewCA:   true,
		CAFile:    "../testdata/ca.pem",
		CAKeyFile: "../testdata/ca-key.pem",
	}
	err = gencertMain([]string{}, c)

	if err != nil {
		t.Fatal(err)
	}
}

func TestGencertFile(t *testing.T) {
	c := cli.Config{
		IsCA:      true,
		CAKeyFile: "file:../testdata/ca-key.pem",
	}

	err := gencertMain([]string{"../testdata/csr.json"}, c)
	if err != nil {
		t.Fatal(err)
	}

	c = cli.Config{
		CAFile:    "file:../testdata/ca.pem",
		CAKeyFile: "file:../testdata/ca-key.pem",
	}

	err = gencertMain([]string{"../testdata/csr.json"}, c)
	if err != nil {
		t.Fatal(err)
	}

	c = cli.Config{
		RenewCA:   true,
		CAFile:    "file:../testdata/ca.pem",
		CAKeyFile: "file:../testdata/ca-key.pem",
	}
	err = gencertMain([]string{}, c)

	if err != nil {
		t.Fatal(err)
	}
}

func TestGencertEnv(t *testing.T) {
	tempCaCert, _ := ioutil.ReadFile("../testdata/ca.pem")
	tempCaKey, _ := ioutil.ReadFile("../testdata/ca-key.pem")
	os.Setenv("ca", string(tempCaCert))
	os.Setenv("ca_key", string(tempCaKey))

	c := cli.Config{
		IsCA:      true,
		CAKeyFile: "env:ca_key",
	}

	err := gencertMain([]string{"../testdata/csr.json"}, c)
	if err != nil {
		t.Fatal(err)
	}

	c = cli.Config{
		CAFile:    "env:ca",
		CAKeyFile: "env:ca_key",
	}

	err = gencertMain([]string{"../testdata/csr.json"}, c)
	if err != nil {
		t.Fatal(err)
	}

	c = cli.Config{
		RenewCA:   true,
		CAFile:    "env:ca",
		CAKeyFile: "env:ca_key",
	}
	err = gencertMain([]string{}, c)

	if err != nil {
		t.Fatal(err)
	}
}

func TestBadGencertEnv(t *testing.T) {
	tempCaCert, _ := ioutil.ReadFile("../testdata/ca.pem")
	tempCaKey, _ := ioutil.ReadFile("../testdata/ca-key.pem")
	os.Setenv("ca", string(tempCaCert))
	os.Setenv("ca_key", string(tempCaKey))

	c := cli.Config{
		RenewCA:   true,
		CAFile:    "ca",
		CAKeyFile: "env:ca_key",
	}
	err := gencertMain([]string{}, c)

	if err == nil {
		t.Fatal("No prefix provided, should report an error")
	}

	c = cli.Config{
		RenewCA:   true,
		CAFile:    "env:ca",
		CAKeyFile: "ca_key",
	}
	err = gencertMain([]string{}, c)

	if err == nil {
		t.Fatal("No prefix provided, should report an error")
	}

	c = cli.Config{
		RenewCA:   true,
		CAFile:    "env:ca",
		CAKeyFile: "en:ca_key",
	}
	err = gencertMain([]string{}, c)

	if err == nil {
		t.Fatal("Unsupported prefix, should report error")
	}

	c = cli.Config{
		RenewCA:   true,
		CAFile:    "env:ca",
		CAKeyFile: "env:file:ca_key",
	}
	err = gencertMain([]string{}, c)

	if err == nil {
		t.Fatal("Multiple prefixes, should report error")
	}
}

func TestBadGencertMain(t *testing.T) {
	err := gencertMain([]string{"../testdata/csr.json"}, cli.Config{})
	if err != nil {
		t.Fatal(err)
	}

	err = gencertMain([]string{"../testdata/csr.json"}, cli.Config{CAFile: "../testdata/ca.pem"})
	if err != nil {
		t.Fatal(err)
	}

	err = gencertMain([]string{}, cli.Config{RenewCA: true})
	if err == nil {
		t.Fatal("No CA or Key provided, should report error")
	}

	err = gencertMain([]string{}, cli.Config{})
	if err == nil {
		t.Fatal("Not enough argument, should report error")
	}

	err = gencertMain([]string{"../testdata/bad_csr.json"}, cli.Config{})
	if err == nil {
		t.Fatal("Bad CSR JSON, should report error")
	}

	err = gencertMain([]string{"../testdata/nothing"}, cli.Config{})
	if err == nil {
		t.Fatal("Trying to read a non-existence file, should report error")
	}

	err = gencertMain([]string{"../testdata/csr.json"}, cli.Config{IsCA: true, CAKeyFile: "../../testdata/garbage.crt"})
	if err == nil {
		t.Fatal("Bad CA, should report error")
	}

	err = gencertMain([]string{"../testdata/csr.json"}, cli.Config{CAFile: "../testdata/ca.pem", Remote: "123::::123"})
	if err == nil {
		t.Fatal("Invalid remote, should reort error")
	}
}

// taken from cli/genkey/genkey_test.go, could be factored in some utils/ package
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

	if response["cert"] == nil {
		return nil, errors.New("no cert is outputted")
	}

	if response["key"] == nil {
		return nil, errors.New("no key is outputted")
	}

	if response["csr"] == nil {
		return nil, errors.New("no csr is outputted")
	}

	return response, nil
}

func TestGencertMainWithConfigLoading(t *testing.T) {

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

	// test: this should use the config specified in "good_config_ca.json" (hence produce a 10-year cert)
	err = gencertMain([]string{"../testdata/csr.json"}, c)
	if err != nil {
		t.Fatal("Could not generate a cert with the config file", err)
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
