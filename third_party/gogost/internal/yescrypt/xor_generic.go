//go:build !amd64 || purego

package yescrypt

func xorWords(dst, src []uint64, n int) {
	for i, value := range src[:n] {
		dst[i] ^= value
	}
}
