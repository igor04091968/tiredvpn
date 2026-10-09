//go:build !amd64 && !arm64 && !386
// +build !amd64,!arm64,!386

package gost3412128

import "encoding/binary"

func getBlock64(src *[BlockSize]byte) (uint64, uint64) {
	return binary.LittleEndian.Uint64(src[0:8]), binary.LittleEndian.Uint64(src[8:16])
}

func putBlock64(dst *[BlockSize]byte, lo, hi uint64) {
	binary.LittleEndian.PutUint64(dst[0:8], lo)
	binary.LittleEndian.PutUint64(dst[8:16], hi)
}

func xorBlock(block *[BlockSize]byte, key *[BlockSize]byte) {
	lo := binary.LittleEndian.Uint64(block[0:8]) ^ binary.LittleEndian.Uint64(key[0:8])
	hi := binary.LittleEndian.Uint64(block[8:16]) ^ binary.LittleEndian.Uint64(key[8:16])
	putBlock64(block, lo, hi)
}
