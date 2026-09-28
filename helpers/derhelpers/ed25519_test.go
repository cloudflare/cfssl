package derhelpers

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/x509"
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

// TestParsePrivateKeyDERMLDSARFC9881 verifies round-trip parsing of the
// ML-DSA-44 example private key from RFC 9881.
func TestParsePrivateKeyDERMLDSARFC9881(t *testing.T) {
	const rfc9881PEM = `-----BEGIN PRIVATE KEY-----
MDQCAQAwCwYJYIZIAWUDBAMRBCKAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ
GhscHR4f
-----END PRIVATE KEY-----`

	block, _ := pem.Decode([]byte(rfc9881PEM))
	if block == nil {
		t.Fatal("failed to decode RFC 9881 PEM")
	}

	parsed, err := ParsePrivateKeyDER(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePrivateKeyDER failed: %v", err)
	}

	mldsaKey, ok := parsed.(*mldsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *mldsa.PrivateKey, got %T", parsed)
	}

	if mldsaKey.PublicKey().Parameters() != mldsa.MLDSA44() {
		t.Fatalf("expected MLDSA44 parameters, got %v", mldsaKey.PublicKey().Parameters())
	}

	// Verify round-trip: marshal back to PKCS#8 and re-parse
	der, err := x509.MarshalPKCS8PrivateKey(mldsaKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey failed: %v", err)
	}

	reparsed, err := ParsePrivateKeyDER(der)
	if err != nil {
		t.Fatalf("ParsePrivateKeyDER round-trip failed: %v", err)
	}

	if !reparsed.(*mldsa.PrivateKey).PublicKey().Equal(mldsaKey.PublicKey()) {
		t.Fatal("public keys differ after round-trip")
	}
}

func TestParsePrivateKeyDERMLDSA(t *testing.T) {
	tests := []struct {
		name   string
		params mldsa.Parameters
	}{
		{"MLDSA44", mldsa.MLDSA44()},
		{"MLDSA65", mldsa.MLDSA65()},
		{"MLDSA87", mldsa.MLDSA87()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			priv, err := mldsa.GenerateKey(tt.params)
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}

			der, err := x509.MarshalPKCS8PrivateKey(priv)
			if err != nil {
				t.Fatalf("MarshalPKCS8PrivateKey failed: %v", err)
			}

			parsed, err := ParsePrivateKeyDER(der)
			if err != nil {
				t.Fatalf("ParsePrivateKeyDER failed: %v", err)
			}

			mldsaKey, ok := parsed.(*mldsa.PrivateKey)
			if !ok {
				t.Fatalf("expected *mldsa.PrivateKey, got %T", parsed)
			}

			if mldsaKey.PublicKey().Parameters() != tt.params {
				t.Fatalf("parameters mismatch after round-trip")
			}
		})
	}
}
