// +build pkcs11

package pkcs11key

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"flag"
	"math/big"
	"runtime"
	"testing"
	"time"
)

var module = flag.String("module", "", "Path to PKCS11 module")
var tokenLabel = flag.String("tokenLabel", "", "Token label")
var pin = flag.String("pin", "", "PIN")
var privateKeyLabel = flag.String("privateKeyLabel", "", "Private key label")
var sessionCount = flag.Int("sessions", runtime.GOMAXPROCS(-1), `Number of PKCS#11 sessions to use.
For SoftHSM, GOMAXPROCS is appropriate, but for an external HSM the optimum session count depends on the HSM's parallelism.`)

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

	pool, err := NewPool(*sessionCount, *module, *tokenLabel, *pin, *privateKeyLabel)
	if err != nil {
		b.Fatal(err)
		return
	}
	defer pool.Destroy()

	instance := pool.get()
	if instance.alwaysAuthenticate {
		b.Log("WARNING: Token has CKA_ALWAYS_AUTHENTICATE attribute, which makes signing slow.")
	}
	pool.put(instance)

	// Reset the benchmarking timer so we don't include setup time.
	b.ResetTimer()

	// Start recording total time. Go's benchmarking code is interested in
	// nanoseconds per op, but we're also interested in the total throughput.
	start := time.Now()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err = x509.CreateCertificate(rand.Reader, &template, &template, template.PublicKey, pool)
			if err != nil {
				b.Fatal(err)
				return
			}
		}
	})

	elapsedTime := time.Now().Sub(start)
	b.Logf("Time, count, ops / second: %s, %d, %g", elapsedTime, b.N, float64(b.N)*float64(time.Second)/float64(elapsedTime))
}

// Dummy test to avoid getting "warning: no tests found"
func TestNothing(t *testing.T) {
}
