//go:build amd64 && !purego

package mgm

import "testing"

func TestPCLMULMatchesGeneric(t *testing.T) {
	if !usePCLMUL {
		t.Skip("PCLMULQDQ is unavailable")
	}
	state := uint64(0x9e3779b97f4a7c15)
	next := func() uint64 {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		return state
	}
	for i := 0; i < 10_000; i++ {
		x, y := next(), next()
		if got, want := gfMul64PCLMUL(x, y), gfMul64Generic(x, y); got != want {
			t.Fatalf("GF(2^64) mismatch at %d: got %016x, want %016x", i, got, want)
		}

		xHi, xLo, yHi, yLo := next(), next(), next(), next()
		gotHi, gotLo := gfMul128PCLMUL(xHi, xLo, yHi, yLo)
		wantHi, wantLo := gfMul128Generic(xHi, xLo, yHi, yLo)
		if gotHi != wantHi || gotLo != wantLo {
			t.Fatalf("GF(2^128) mismatch at %d: got %016x%016x, want %016x%016x", i, gotHi, gotLo, wantHi, wantLo)
		}
	}
}
