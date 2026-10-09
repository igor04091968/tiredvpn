//go:build amd64 && !purego && gostsimdresearch
// +build amd64,!purego,gostsimdresearch

package gost341264

import (
	"bytes"
	"testing"
)

var magmaBitsliceANF = makeMagmaBitsliceANF()

func makeMagmaBitsliceANF() [8][4]uint16 {
	var out [8][4]uint16
	for row := 0; row < 8; row++ {
		for bit := 0; bit < 4; bit++ {
			var values [16]byte
			for x := 0; x < 16; x++ {
				values[x] = (magmaSbox[row][x] >> bit) & 1
			}
			for i := 0; i < 4; i++ {
				step := 1 << i
				for mask := 0; mask < 16; mask++ {
					if mask&step != 0 {
						values[mask] ^= values[mask^step]
					}
				}
			}
			var coeff uint16
			for mask := 0; mask < 16; mask++ {
				if values[mask] != 0 {
					coeff |= 1 << mask
				}
			}
			out[row][bit] = coeff
		}
	}
	return out
}

func packBitslice32(src []byte, n1, n2 *[32]uint32) {
	for i := 0; i < 32; i++ {
		n1[i], n2[i] = 0, 0
	}
	for lane := 0; lane < 32; lane++ {
		block := src[lane*BlockSize:]
		left := load32BE(block[0:4])
		right := load32BE(block[4:8])
		mask := uint32(1) << lane
		for bit := 0; bit < 32; bit++ {
			if right&(1<<bit) != 0 {
				n1[bit] |= mask
			}
			if left&(1<<bit) != 0 {
				n2[bit] |= mask
			}
		}
	}
}

func unpackBitslice32(dst []byte, n1, n2 *[32]uint32) {
	for lane := 0; lane < 32; lane++ {
		mask := uint32(1) << lane
		var left, right uint32
		for bit := 0; bit < 32; bit++ {
			if n1[bit]&mask != 0 {
				left |= 1 << bit
			}
			if n2[bit]&mask != 0 {
				right |= 1 << bit
			}
		}
		block := dst[lane*BlockSize:]
		store32BE(block[0:4], left)
		store32BE(block[4:8], right)
	}
}

func bitsliceAddConst32(x *[32]uint32, k word) {
	var carry uint32
	for bit := 0; bit < 32; bit++ {
		a := x[bit]
		var kb uint32
		if (uint32(k)>>bit)&1 != 0 {
			kb = ^uint32(0)
		}
		x[bit] = a ^ kb ^ carry
		carry = (a & kb) | (a & carry) | (kb & carry)
	}
}

func bitsliceSboxRow32(x0, x1, x2, x3 uint32, coeff [4]uint16) (uint32, uint32, uint32, uint32) {
	mon := [16]uint32{
		^uint32(0),
		x0,
		x1,
		x0 & x1,
		x2,
		x0 & x2,
		x1 & x2,
		x0 & x1 & x2,
		x3,
		x0 & x3,
		x1 & x3,
		x0 & x1 & x3,
		x2 & x3,
		x0 & x2 & x3,
		x1 & x2 & x3,
		x0 & x1 & x2 & x3,
	}
	var out [4]uint32
	for bit := 0; bit < 4; bit++ {
		c := coeff[bit]
		var v uint32
		for mask := 0; mask < 16; mask++ {
			if c&(1<<mask) != 0 {
				v ^= mon[mask]
			}
		}
		out[bit] = v
	}
	return out[0], out[1], out[2], out[3]
}

func bitsliceSubstRotate32(x *[32]uint32) {
	var y [32]uint32
	for row := 0; row < 8; row++ {
		i := row * 4
		y[i], y[i+1], y[i+2], y[i+3] = bitsliceSboxRow32(
			x[i], x[i+1], x[i+2], x[i+3],
			magmaBitsliceANF[row],
		)
	}
	var rotated [32]uint32
	for bit := 0; bit < 32; bit++ {
		rotated[(bit+11)&31] = y[bit]
	}
	*x = rotated
}

func cryptBlocksBitslice32Research(dst, src []byte, keys *[32]word) {
	var n1, n2 [32]uint32
	for len(src) >= 32*BlockSize {
		packBitslice32(src[:32*BlockSize], &n1, &n2)
		for round := 0; round < 32; round++ {
			old := n1
			bitsliceAddConst32(&n1, keys[round])
			bitsliceSubstRotate32(&n1)
			for bit := 0; bit < 32; bit++ {
				n1[bit], n2[bit] = n1[bit]^n2[bit], old[bit]
			}
		}
		unpackBitslice32(dst[:32*BlockSize], &n1, &n2)
		src = src[32*BlockSize:]
		dst = dst[32*BlockSize:]
	}
}

func TestBitslice32ResearchEquivalent(t *testing.T) {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i*19 + 7)
	}
	c := NewCipher(key)
	src := benchMagmaData(32 * BlockSize)
	want := make([]byte, len(src))
	for off := 0; off < len(src); off += BlockSize {
		c.Encrypt(want[off:off+BlockSize], src[off:off+BlockSize])
	}
	got := make([]byte, len(src))
	cryptBlocksBitslice32Research(got, src, &c.encKeys)
	if !bytes.Equal(got, want) {
		t.Fatalf("bitslice32 research encrypt mismatch\nwant %x\ngot  %x", want[:BlockSize], got[:BlockSize])
	}
	plain := make([]byte, len(src))
	cryptBlocksBitslice32Research(plain, got, &c.decKeys)
	if !bytes.Equal(plain, src) {
		t.Fatalf("bitslice32 research decrypt mismatch\nwant %x\ngot  %x", src[:BlockSize], plain[:BlockSize])
	}
}

func BenchmarkBitslice32Research(b *testing.B) {
	c := NewCipher(benchMagmaKey())
	for _, size := range []struct {
		name string
		n    int
	}{
		{"1KiB", 1024},
		{"16KiB", 16 * 1024},
		{"1MiB", 1 << 20},
	} {
		src := benchMagmaData(size.n)
		dst := make([]byte, size.n)
		encrypted := make([]byte, size.n)
		c.EncryptBlocks(encrypted, src)

		b.Run("Encrypt/"+size.name, func(b *testing.B) {
			n := len(src) / (32 * BlockSize) * (32 * BlockSize)
			b.SetBytes(int64(n))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				cryptBlocksBitslice32Research(dst[:n], src[:n], &c.encKeys)
			}
			copy(benchMagmaOut[:], dst[:n])
		})
		b.Run("Decrypt/"+size.name, func(b *testing.B) {
			n := len(encrypted) / (32 * BlockSize) * (32 * BlockSize)
			b.SetBytes(int64(n))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				cryptBlocksBitslice32Research(dst[:n], encrypted[:n], &c.decKeys)
			}
			copy(benchMagmaOut[:], dst[:n])
		})
	}
}
