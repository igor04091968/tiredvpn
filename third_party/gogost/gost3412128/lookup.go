//go:build !amd64 && !arm64
// +build !amd64,!arm64

package gost3412128

import "encoding/binary"

func lookupTableBlock(dst, src *[BlockSize]byte, table *[16][256][16]uint8) {
	entry := &table[0][src[0]]
	lo := binary.LittleEndian.Uint64(entry[0:8])
	hi := binary.LittleEndian.Uint64(entry[8:16])

	for i := 1; i < BlockSize; i++ {
		entry = &table[i][src[i]]
		lo ^= binary.LittleEndian.Uint64(entry[0:8])
		hi ^= binary.LittleEndian.Uint64(entry[8:16])
	}

	binary.LittleEndian.PutUint64(dst[0:8], lo)
	binary.LittleEndian.PutUint64(dst[8:16], hi)
}
