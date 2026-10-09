package mgm

import (
	"crypto/rand"
	"testing"

	"gitverse.ru/uzer_007/gogost/v3/gost341264"
)

func BenchmarkMul64(b *testing.B) {
	x := make([]byte, gost341264.BlockSize)
	y := make([]byte, gost341264.BlockSize)
	rand.Read(x)
	rand.Read(y)
	mul := newMul64()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mul.Mul(x, y)
	}
}
