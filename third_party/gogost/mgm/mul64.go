package mgm

import (
	"encoding/binary"
)

const Mul64MaxBit = 64 - 1

type mul64 struct{ buf [8]byte }

func newMul64() *mul64 { return &mul64{} }

func gfMul64Generic(xv, yv uint64) uint64 {
	var zv uint64
	for i := 0; i < 64; i++ {
		mask := uint64(0) - (yv & 1)
		zv ^= xv & mask
		carry := xv >> 63
		xv = (xv << 1) ^ (0x1b & (uint64(0) - carry))
		yv >>= 1
	}
	return zv
}

func mulAdd64(sum, x, y []byte) {
	zv := gfMul64(binary.BigEndian.Uint64(x), binary.BigEndian.Uint64(y))
	binary.BigEndian.PutUint64(sum, binary.BigEndian.Uint64(sum)^zv)
}

// Mul возвращает произведение x и y в GF(2^64).
func (mul *mul64) Mul(x, y []byte) []byte {
	binary.BigEndian.PutUint64(mul.buf[:], gfMul64(
		binary.BigEndian.Uint64(x),
		binary.BigEndian.Uint64(y),
	))
	return mul.buf[:]
}
