//go:build arm64 && !purego

package gost3410

func fixedMulArchAvailable() bool { return true }

func fixedAddMulArch(z, x *uint64, y uint64, words int) uint64 {
	if words == 4 {
		return fixedAddMul4ARM64(z, x, y)
	}
	return fixedAddMul8ARM64(z, x, y)
}

//go:noescape
func fixedAddMul4ARM64(z, x *uint64, y uint64) (carry uint64)

//go:noescape
func fixedAddMul8ARM64(z, x *uint64, y uint64) (carry uint64)
