//go:build amd64 || arm64 || 386
// +build amd64 arm64 386

package gost3412128

import "unsafe"

func getBlock64(src *[BlockSize]byte) (uint64, uint64) {
	return *(*uint64)(unsafe.Pointer(&src[0])), *(*uint64)(unsafe.Pointer(&src[8]))
}

func putBlock64(dst *[BlockSize]byte, lo, hi uint64) {
	*(*uint64)(unsafe.Pointer(&dst[0])) = lo
	*(*uint64)(unsafe.Pointer(&dst[8])) = hi
}

func xorBlock(block *[BlockSize]byte, key *[BlockSize]byte) {
	lo := *(*uint64)(unsafe.Pointer(&block[0])) ^ *(*uint64)(unsafe.Pointer(&key[0]))
	hi := *(*uint64)(unsafe.Pointer(&block[8])) ^ *(*uint64)(unsafe.Pointer(&key[8]))
	putBlock64(block, lo, hi)
}
