package pkcs11key

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"flag"
	"math/big"
	"testing"
	"time"
)

var module = flag.String("module", "", "Path to PKCS11 module")
var tokenLabel = flag.String("tokenLabel", "", "Token label")
var pin = flag.String("pin", "", "PIN")
var privateKeyLabel = flag.String("privateKeyLabel", "", "Private key label")

// BenchmarkPKCS11 signs a certificate repeatedly using a PKCS11 token and
// measures speed. To run (with SoftHSM):
// go test -bench=. -benchtime 5s ./crypto/pkcs11key/ \
//   -module /usr/lib/softhsm/libsofthsm.so -token-label "softhsm token" \
//   -pin 1234 -private-key-label "my key" -cpu 4
// You can adjust benchtime if you want to run for longer or shorter, and change
// the number of CPUs to select the parallelism you want.
func BenchmarkPKCS11(b *testing.B) {
	if *module == "" || *tokenLabel == "" || *pin == "" || *privateKeyLabel == "" {
		b.Fatal("Must pass all flags: module, tokenLabel, pin, and privateKeyLabel")
		return
	}

	// A minimal, bogus certificate to be signed.
	// Note: we choose a large N to make up for some of the missing fields in the
	// bogus certificate, so we wind up something approximately the size of a real
	// certificate.
	N := big.NewInt(1)
	N.Lsh(N, 6000)
	template := x509.Certificate{
		SerialNumber:       big.NewInt(1),
		PublicKeyAlgorithm: x509.RSA,
		NotBefore:          time.Now(),
		NotAfter:           time.Now(),

		PublicKey: &rsa.PublicKey{
			N: N,
			E: 1 << 17,
		},
	}

	// Login once to make sure the PIN works. This avoids repeatedly logging in
	// with bad credentials, which would pin-lock the token.
	firstKey, err := New(*module, *tokenLabel, *pin, *privateKeyLabel)
	if err != nil {
		b.Fatal(err)
		return
	}
	firstKey.Destroy()

	// Reset the benchmarking timer so we don't include setup time.
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		p, err := New(*module, *tokenLabel, *pin, *privateKeyLabel)
		if err != nil {
			b.Fatal(err)
			return
		}
		defer p.Destroy()

		for pb.Next() {
			_, err = x509.CreateCertificate(rand.Reader, &template, &template, template.PublicKey, p)
			if err != nil {
				b.Fatal(err)
				return
			}
		}
	})
}

// Dummy test to avoid getting "warning: no tests found"
func TestNothing(t *testing.T) {
}
