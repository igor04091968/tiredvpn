package gost3410

import (
	"math/bits"
	"math/rand"
	"testing"
)

type fixedAddMulFunc func(z, x *uint64, y uint64) uint64

func testFixedAddMulPrimitive(t *testing.T, words int, primitive fixedAddMulFunc) {
	t.Helper()
	random := rand.New(rand.NewSource(0xadb3410))
	for iteration := 0; iteration < 1024; iteration++ {
		x := make([]uint64, words)
		got := make([]uint64, words)
		want := make([]uint64, words)
		for i := range words {
			x[i] = random.Uint64()
			got[i] = random.Uint64()
			want[i] = got[i]
		}
		y := random.Uint64()
		carry := uint64(0)
		for i := range words {
			hi, lo := bits.Mul64(x[i], y)
			var c uint64
			lo, c = bits.Add64(lo, want[i], 0)
			hi, _ = bits.Add64(hi, 0, c)
			lo, c = bits.Add64(lo, carry, 0)
			hi, _ = bits.Add64(hi, 0, c)
			want[i] = lo
			carry = hi
		}
		gotCarry := primitive(&got[0], &x[0], y)
		if gotCarry != carry {
			t.Fatalf("iteration %d: carry = %x, want %x", iteration, gotCarry, carry)
		}
		for i := range words {
			if got[i] != want[i] {
				t.Fatalf("iteration %d word %d = %x, want %x", iteration, i, got[i], want[i])
			}
		}
	}
}
