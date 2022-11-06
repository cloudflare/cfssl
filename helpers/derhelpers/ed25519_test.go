package derhelpers

import (
	"bytes"
	"crypto/ed25519"
	"encoding/pem"
	"testing"
)

var testPubKey = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PUBLIC KEY-----
`

var testPrivKey = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
-----END PRIVATE KEY-----`

func TestParseMarshalEd25519PublicKey(t *testing.T) {
	block, rest := pem.Decode([]byte(testPubKey))
	if len(rest) > 0 {
		t.Fatal("pem.Decode(); len(rest) > 0, want 0")
	}

	pk, err := ParseEd25519PublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	if pkLen := len(pk.(ed25519.PublicKey)); pkLen != 32 {
		t.Fatalf("len(pk): got %d: want %d", pkLen, 32)
	}

	der, err := MarshalEd25519PublicKey(pk)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(der, block.Bytes) {
		t.Errorf("got %d bytes:\n%v \nwant %d bytes:\n%v",
			len(der), der, len(block.Bytes), block.Bytes)
	}
}

func TestParseMarshalEd25519PrivateKey(t *testing.T) {
	block, rest := pem.Decode([]byte(testPrivKey))
	if len(rest) > 0 {
		t.Fatal("pem.Decode(); len(rest) > 0, want 0")
	}

	sk, err := ParseEd25519PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	if skLen := len(sk.(ed25519.PrivateKey)); skLen != 64 {
		t.Fatalf("len(sk): got %d: want %d", skLen, 64)
	}

	der, err := MarshalEd25519PrivateKey(sk)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(der, block.Bytes) {
		t.Errorf("got %d bytes:\n%v \nwant %d bytes:\n%v",
			len(der), der, len(block.Bytes), block.Bytes)
	}
}

func TestKeyPair(t *testing.T) {
	block, rest := pem.Decode([]byte(testPrivKey))
	if len(rest) > 0 {
		t.Fatal("pem.Decode(); len(rest) > 0, want 0")
	}

	sk, err := ParseEd25519PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	block, rest = pem.Decode([]byte(testPubKey))
	if len(rest) > 0 {
		t.Fatal("pem.Decode(); len(rest) > 0, want 0")
	}

	pub, err := ParseEd25519PublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	pk := pub.(ed25519.PublicKey)
	pk2 := sk.(ed25519.PrivateKey).Public().(ed25519.PublicKey)
	if !bytes.Equal(pk, pk2) {
		t.Errorf("pk %d bytes:\n%v \nsk.Public() %d bytes:\n%v",
			len(pk), pk, len(pk2), pk2)
	}
}
