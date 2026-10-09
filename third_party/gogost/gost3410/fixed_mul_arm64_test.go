//go:build arm64 && !purego

package gost3410

import "testing"

func TestFixedAddMulARM64(t *testing.T) {
	t.Run("256", func(t *testing.T) {
		testFixedAddMulPrimitive(t, 4, fixedAddMul4ARM64)
	})
	t.Run("512", func(t *testing.T) {
		testFixedAddMulPrimitive(t, 8, fixedAddMul8ARM64)
	})
}
