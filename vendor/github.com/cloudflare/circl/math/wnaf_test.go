package math

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func TestOmegaNAF(t *testing.T) {
	testTimes := 1 << 7
	var max big.Int
	max.SetInt64(1)
	max.Lsh(&max, 128)

	for w := uint(2); w < 10; w++ {
		for j := 0; j < testTimes; j++ {
			x, _ := rand.Int(rand.Reader, &max)
			L := OmegaNAF(x, w)

			var y big.Int
			for i := len(L) - 1; i >= 0; i-- {
				y.Add(&y, &y).Add(&y, big.NewInt(int64(L[i])))
			}
			want := x
			got := &y
			if got.Cmp(want) != 0 {
				test.ReportError(t, got, want, x, w)
			}
		}
	}
}

func TestOmegaNAFRegular(t *testing.T) {
	testTimes := 1 << 7
	Two128 := big.NewInt(1)
	Two128.Lsh(Two128, 128)

	for w := uint(2); w < 10; w++ {
		for j := 0; j < testTimes; j++ {
			x, _ := rand.Int(rand.Reader, Two128)
			x.SetBit(x, 0, uint(1)) // odd-numbers
			L := SignedDigit(x, w, 128)

			var y big.Int
			for i := len(L) - 1; i >= 0; i-- {
				y.Lsh(&y, w-1)
				y.Add(&y, big.NewInt(int64(L[i])))
			}
			want := x
			got := &y
			if got.Cmp(want) != 0 {
				test.ReportError(t, got, want, x, w)
			}
		}
	}
}

func BenchmarkOmegaNAF(b *testing.B) {
	Two128 := big.NewInt(1)
	Two128.Lsh(Two128, 128)

	for w := uint(2); w < 6; w++ {
		b.Run(fmt.Sprintf("%v", w), func(b *testing.B) {
			x, _ := rand.Int(rand.Reader, Two128)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = OmegaNAF(x, w)
			}
		})
	}
}

func BenchmarkOmegaNAFRegular(b *testing.B) {
	Two128 := big.NewInt(1)
	Two128.Lsh(Two128, 128)

	for w := uint(2); w < 6; w++ {
		b.Run(fmt.Sprintf("%v", w), func(b *testing.B) {
			x, _ := rand.Int(rand.Reader, Two128)
			x.SetBit(x, 0, uint(1)) // odd-numbers
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = SignedDigit(x, w, 128)
			}
		})
	}
}
