//go:build amd64 && !purego

package gost3410

import (
	"testing"

	"golang.org/x/sys/cpu"
)

func TestFixedAddMulADX(t *testing.T) {
	if !cpu.X86.HasADX || !cpu.X86.HasBMI2 {
		t.Skip("ADX/BMI2 are unavailable")
	}
	t.Run("256", func(t *testing.T) {
		testFixedAddMulPrimitive(t, 4, fixedAddMul4ADX)
	})
	t.Run("512", func(t *testing.T) {
		testFixedAddMulPrimitive(t, 8, fixedAddMul8ADX)
	})
}
