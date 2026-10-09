package mgm

import "encoding/binary"

type mul128 struct{ buf [16]byte }

func newMul128() *mul128 {
	return &mul128{}
}

func gfMul128Generic(xHi, xLo, yHi, yLo uint64) (uint64, uint64) {
	var zHi, zLo uint64
	for i := 0; i < 128; i++ {
		var t uint64
		if i < 64 {
			t = yLo
			yLo >>= 1
		} else {
			t = yHi
			yHi >>= 1
		}
		mask := uint64(0) - (t & 1)
		zHi ^= xHi & mask
		zLo ^= xLo & mask
		carry := xHi >> 63
		xHi = (xHi << 1) ^ (xLo >> 63)
		xLo = (xLo << 1) ^ (0x87 & (uint64(0) - carry))
	}
	return zHi, zLo
}

func mulAdd128(sum, x, y []byte) {
	zHi, zLo := gfMul128(
		binary.BigEndian.Uint64(x[:8]),
		binary.BigEndian.Uint64(x[8:]),
		binary.BigEndian.Uint64(y[:8]),
		binary.BigEndian.Uint64(y[8:]),
	)
	binary.BigEndian.PutUint64(sum[:8], binary.BigEndian.Uint64(sum[:8])^zHi)
	binary.BigEndian.PutUint64(sum[8:], binary.BigEndian.Uint64(sum[8:])^zLo)
}

func gf128half(n int, t, x0, x1, z0, z1 uint64) (uint64, uint64, uint64, uint64, uint64) {
	for i := 0; i < n; i++ {
		mask := uint64(0) - (t & 1)
		z0 ^= x0 & mask
		z1 ^= x1 & mask
		t >>= 1
		sign := x1 >> 63
		x1 = (x1 << 1) ^ (x0 >> 63)
		x0 = (x0 << 1) ^ (0x87 & (uint64(0) - sign))
	}
	return t, x0, x1, z0, z1
}

func (mul *mul128) Mul(x, y []byte) []byte {
	zHi, zLo := gfMul128(
		binary.BigEndian.Uint64(x[:8]),
		binary.BigEndian.Uint64(x[8:]),
		binary.BigEndian.Uint64(y[:8]),
		binary.BigEndian.Uint64(y[8:]),
	)
	binary.BigEndian.PutUint64(mul.buf[:8], zHi)
	binary.BigEndian.PutUint64(mul.buf[8:], zLo)
	return mul.buf[:]
}
