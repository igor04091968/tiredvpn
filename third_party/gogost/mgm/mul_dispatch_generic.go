//go:build !amd64 || purego

package mgm

func gfMul64(x, y uint64) uint64 {
	return gfMul64Generic(x, y)
}

func gfMul128(xHi, xLo, yHi, yLo uint64) (uint64, uint64) {
	return gfMul128Generic(xHi, xLo, yHi, yLo)
}
