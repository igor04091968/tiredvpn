//go:build amd64 && !purego

package mgm

import "golang.org/x/sys/cpu"

var usePCLMUL = cpu.X86.HasPCLMULQDQ && cpu.X86.HasSSE41

//go:noescape
func gfMul64PCLMUL(x, y uint64) uint64

//go:noescape
func gfMul128PCLMUL(xHi, xLo, yHi, yLo uint64) (zHi, zLo uint64)

func gfMul64(x, y uint64) uint64 {
	if usePCLMUL {
		return gfMul64PCLMUL(x, y)
	}
	return gfMul64Generic(x, y)
}

func gfMul128(xHi, xLo, yHi, yLo uint64) (uint64, uint64) {
	if usePCLMUL {
		return gfMul128PCLMUL(xHi, xLo, yHi, yLo)
	}
	return gfMul128Generic(xHi, xLo, yHi, yLo)
}
