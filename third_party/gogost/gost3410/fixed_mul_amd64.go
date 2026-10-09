//go:build amd64 && !purego

package gost3410

import "golang.org/x/sys/cpu"

func fixedMulArchAvailable() bool {
	return cpu.X86.HasADX && cpu.X86.HasBMI2
}

func fixedAddMulArch(z, x *uint64, y uint64, words int) uint64 {
	if words == 4 {
		return fixedAddMul4ADX(z, x, y)
	}
	return fixedAddMul8ADX(z, x, y)
}

//go:noescape
func fixedAddMul4ADX(z, x *uint64, y uint64) (carry uint64)

//go:noescape
func fixedAddMul8ADX(z, x *uint64, y uint64) (carry uint64)
