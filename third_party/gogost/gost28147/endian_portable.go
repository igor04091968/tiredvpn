//go:build purego || (!amd64 && !arm64 && !386)

package gost28147

import "encoding/binary"

func load32LE(b []byte) uint32 {
	return binary.LittleEndian.Uint32(b)
}

func store32LE(b []byte, v uint32) {
	binary.LittleEndian.PutUint32(b, v)
}
