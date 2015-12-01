package pkcs11uri

import (
	"fmt"
	"testing"

	"github.com/cloudflare/cfssl/crypto/pkcs11key"
)

type pkcs11UriTest struct {
	URI    string
	Config *pkcs11key.Config
}

func cmpConfigs(a, b *pkcs11key.Config) bool {
	if a == nil {
		if b == nil {
			return true
		}
		return false
	}

	if b == nil {
		return false
	}

	return (a.Module == b.Module) &&
		(a.TokenLabel == b.TokenLabel) &&
		(a.PIN == b.PIN) &&
		(a.PrivateKeyLabel == b.PrivateKeyLabel)
}

func diffConfigs(want, have *pkcs11key.Config) {
	if have == nil && want != nil {
		fmt.Printf("Expected config, have nil.")
		return
	} else if have == nil && want == nil {
		return
	}

	diff := func(kind, v1, v2 string) {
		if v1 != v2 {
			fmt.Printf("%s: want '%s', have '%s'\n", kind, v1, v2)
		}
	}

	diff("Module", want.Module, have.Module)
	diff("TokenLabel", want.TokenLabel, have.TokenLabel)
	diff("PIN", want.PIN, have.PIN)
	diff("PrivateKeyLabel", want.PrivateKeyLabel, have.PrivateKeyLabel)
}

/* Config from PKCS #11 signer
type Config struct {
	Module string
	Token  string
	PIN    string
	Label  string
}
*/

var pkcs11UriCases = []pkcs11UriTest{
	{"pkcs11:token=Software%20PKCS%2311%20softtoken;manufacturer=Snake%20Oil,%20Inc.?pin-value=the-pin",
		&pkcs11key.Config{
			TokenLabel: "Software PKCS#11 softtoken",
			PIN:        "the-pin",
		}},
	{"pkcs11:token=Sun%20Token",
		&pkcs11key.Config{
			TokenLabel: "Sun Token",
		}},
	{"pkcs11:object=test-privkey;token=test-token?pin-source=file:testdata/pin&module-name=test-module",
		&pkcs11key.Config{
			PrivateKeyLabel: "test-privkey",
			TokenLabel:      "test-token",
			PIN:             "123456",
			Module:          "test-module",
		}},
}

func TestParseSuccess(t *testing.T) {
	for _, c := range pkcs11UriCases {
		cfg, err := Parse(c.URI)
		if err != nil {
			t.Fatalf("Failed on URI '%s'", c.URI)
		}
		if !cmpConfigs(c.Config, cfg) {
			diffConfigs(c.Config, cfg)
			t.Fatal("Configs don't match.")
		}
	}
}

var pkcs11UriFails = []string{
	"https://github.com/cloudflare/cfssl",
	"pkcs11:?pin-source=http://foo",
	"pkcs11:?pin-source=file:testdata/nosuchfile",
}

func TestParseFail(t *testing.T) {
	for _, c := range pkcs11UriFails {
		_, err := Parse(c)
		if err == nil {
			t.Fatalf("Expected URI '%s' to fail to parse.", c)
		}
	}
}
