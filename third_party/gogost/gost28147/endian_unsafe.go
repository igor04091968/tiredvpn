//go:build (amd64 || arm64 || 386) && !purego

package gost28147

import "unsafe"

func load32LE(b []byte) uint32 {
	_ = b[3]
	return *(*uint32)(unsafe.Pointer(&b[0]))
}

func store32LE(b []byte, v uint32) {
	_ = b[3]
	*(*uint32)(unsafe.Pointer(&b[0])) = v
}
