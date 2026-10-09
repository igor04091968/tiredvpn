//go:build amd64 || arm64
// +build amd64 arm64

package gost3412128

import "unsafe"

func lookupTableBlock(dst, src *[BlockSize]byte, table *[16][256][16]uint8) {
	entry := &table[0][src[0]]
	lo := *(*uint64)(unsafe.Pointer(&entry[0]))
	hi := *(*uint64)(unsafe.Pointer(&entry[8]))

	for i := 1; i < BlockSize; i++ {
		entry = &table[i][src[i]]
		lo ^= *(*uint64)(unsafe.Pointer(&entry[0]))
		hi ^= *(*uint64)(unsafe.Pointer(&entry[8]))
	}

	*(*uint64)(unsafe.Pointer(&dst[0])) = lo
	*(*uint64)(unsafe.Pointer(&dst[8])) = hi
}
