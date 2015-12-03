package sign

import (
	"testing"

	"github.com/cloudflare/cfssl/cli"
)

func TestSignFromCongif(t *testing.T) {
	_, err := SignerFromConfig(cli.Config{CAFile: "../../testdata/server.crt",
		CAKeyFile: "../../testdata/server.key", Hostname: "www.cloudflare.com", Remote: "127.0.0.1:8888"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignerMain(t *testing.T) {
	err := signerMain([]string{"../../testdata/server.csr"}, cli.Config{CAFile: "../../testdata/server.crt",
		CAKeyFile: "../../testdata/server.key", Hostname: "www.cloudflare.com"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestBadSigner(t *testing.T) {
	err := signerMain([]string{"../../testdata/server.csr"}, cli.Config{CAFile: "", CAKeyFile: ""})
	if err != nil {
		t.Fatal(err)
	}
	err = signerMain([]string{"../../testdata/server.csr"},
		cli.Config{CAFile: "../../testdata/server.crt", CAKeyFile: ""})
	if err != nil {
		t.Fatal(err)
	}
}
