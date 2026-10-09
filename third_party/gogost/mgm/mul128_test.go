package mgm

import (
	"crypto/rand"
	"testing"

	"gitverse.ru/uzer_007/gogost/v3/gost3412128"
)

func BenchmarkMul128(b *testing.B) {
	x := make([]byte, gost3412128.BlockSize)
	y := make([]byte, gost3412128.BlockSize)
	rand.Read(x)
	rand.Read(y)
	mul := newMul128()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mul.Mul(x, y)
	}
}
