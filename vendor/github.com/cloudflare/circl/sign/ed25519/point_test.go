package ed25519

import (
	"crypto/rand"
	"flag"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func randomPoint(P *pointR1) {
	k := make([]byte, Size)
	_, _ = rand.Read(k[:])
	P.fixedMult(k)
}

func TestPoint(t *testing.T) {
	const testTimes = 1 << 10

	t.Run("add", func(t *testing.T) {
		var P pointR1
		var Q pointR1
		var R pointR2
		for i := 0; i < testTimes; i++ {
			randomPoint(&P)
			_16P := P
			R.fromR1(&P)
			// 16P = 2^4P
			for j := 0; j < 4; j++ {
				_16P.double()
			}
			// 16P = P+P...+P
			Q.SetIdentity()
			for j := 0; j < 16; j++ {
				Q.add(&R)
			}

			got := _16P.isEqual(&Q)
			want := true
			if got != want {
				test.ReportError(t, got, want, P)
			}
		}
	})

	t.Run("fixed", func(t *testing.T) {
		var P, Q, R pointR1
		k := make([]byte, Size)
		l := make([]byte, Size)
		for i := 0; i < testTimes; i++ {
			randomPoint(&P)
			_, _ = rand.Read(k[:])

			Q.fixedMult(k[:])
			R.doubleMult(&P, k[:], l[:])

			got := Q.isEqual(&R)
			want := true
			if got != want {
				test.ReportError(t, got, want, P, k)
			}
		}
	})
}

var runLongBench = flag.Bool("long", false, "runs longer benchmark")

func BenchmarkPoint(b *testing.B) {
	if !*runLongBench {
		b.Log("Skipped one long bench, add -long flag to run longer bench")
		b.SkipNow()
	}

	k := make([]byte, Size)
	l := make([]byte, Size)
	_, _ = rand.Read(k)
	_, _ = rand.Read(l)

	var P pointR1
	var Q pointR2
	var R pointR3
	randomPoint(&P)
	Q.fromR1(&P)
	b.Run("toAffine", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P.toAffine()
		}
	})
	b.Run("double", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P.double()
		}
	})
	b.Run("mixadd", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P.mixAdd(&R)
		}
	})
	b.Run("add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P.add(&Q)
		}
	})
	b.Run("fixedMult", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P.fixedMult(k)
		}
	})
	b.Run("doubleMult", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P.doubleMult(&P, k, l)
		}
	})
}
