//go:build amd64 && !purego

package gost28147

import (
	"crypto/subtle"
	"unsafe"
)

func cpuid(eaxArg, ecxArg uint32) (eax, ebx, ecx, edx uint32)
func xgetbv(index uint32) (eax, edx uint32)

//go:noescape
func cryptBlocksAVX2(dst, src unsafe.Pointer, n uintptr, keys *[32]nv, sbox *[8][32]byte)

var useAVX2 = hasAVX2()

var (
	simdNibbleMask = [32]byte{
		0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f,
		0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f,
		0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f,
		0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f,
	}
	simdPos0Mask = [32]byte{0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0}
	simdPos1Mask = [32]byte{0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0}
	simdPos2Mask = [32]byte{0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0}
	simdPos3Mask = [32]byte{0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff}
	simdPermN1   = [8]uint32{0, 2, 4, 6, 0, 0, 0, 0}
	simdPermN2   = [8]uint32{1, 3, 5, 7, 0, 0, 0, 0}
)

const (
	encryptBlocksAVX2Min = 8 * BlockSize
	decryptBlocksAVX2Min = 8 * BlockSize
)

func encryptBlocksSIMD(dst, src []byte, keys *[32]nv, sbox *[8][32]byte) int {
	return cryptBlocksSIMDMin(dst, src, keys, sbox, encryptBlocksAVX2Min)
}

func decryptBlocksSIMD(dst, src []byte, keys *[32]nv, sbox *[8][32]byte) int {
	return cryptBlocksSIMDMin(dst, src, keys, sbox, decryptBlocksAVX2Min)
}

func cryptBlocksSIMDMin(dst, src []byte, keys *[32]nv, sbox *[8][32]byte, min int) int {
	if !useAVX2 {
		return 0
	}
	if len(src) >= min {
		n := len(src) &^ (8*BlockSize - 1)
		cryptBlocksAVX2(unsafe.Pointer(&dst[0]), unsafe.Pointer(&src[0]), uintptr(n), keys, sbox)
		return n
	}
	if len(src) >= 5*BlockSize {
		var in, out [8 * BlockSize]byte
		copy(in[:], src)
		cryptBlocksAVX2(unsafe.Pointer(&out[0]), unsafe.Pointer(&in[0]), uintptr(len(in)), keys, sbox)
		copy(dst, out[:len(src)])
		return len(src)
	}
	return 0
}

func xorKeyStreamCTRSIMD(ctr *CTR, dst, src []byte) int {
	if !useAVX2 || len(src) < 1024 {
		return 0
	}
	return xorKeyStreamCTRBufferedAVX2(ctr, dst, src)
}

func xorKeyStreamGOST3413CTRSIMD(c *Cipher, dst, src, counter []byte) int {
	if !useAVX2 || len(src) < 1024 {
		return 0
	}
	total := len(src) &^ (8*BlockSize - 1)
	const chunk = 4096
	var counters [chunk]byte
	var gamma [chunk]byte
	left0 := load32LE(counter[0:4])
	right := load32BE(counter[4:8])
	done := 0
	for done < total {
		n := total - done
		if n > chunk {
			n = chunk
		}
		r := right
		for off := 0; off < n; off += BlockSize {
			store32LE(counters[off:off+4], left0)
			store32BE(counters[off+4:off+8], r)
			r++
		}
		cryptBlocksAVX2(unsafe.Pointer(&gamma[0]), unsafe.Pointer(&counters[0]), uintptr(n), &c.encKeys, &c.simdSbox)
		subtle.XORBytes(dst[done:done+n], src[done:done+n], gamma[:n])
		done += n
		right = r
	}
	store32BE(counter[4:8], right)
	return done
}

func xorKeyStreamCTRBufferedAVX2(ctr *CTR, dst, src []byte) int {
	total := len(src) &^ (8*BlockSize - 1)
	const chunk = 4096
	var counters [chunk]byte
	var gamma [chunk]byte
	done := 0
	for done < total {
		n := total - done
		if n > chunk {
			n = chunk
		}
		for off := 0; off < n; off += BlockSize {
			ctr.n1 += 0x01010101
			ctr.n2 += 0x01010104
			if ctr.n2 >= (1<<32)-1 {
				ctr.n2 -= (1 << 32) - 1
			}
			store32LE(counters[off:off+4], uint32(ctr.n1))
			store32LE(counters[off+4:off+8], uint32(ctr.n2))
		}
		cryptBlocksAVX2(unsafe.Pointer(&gamma[0]), unsafe.Pointer(&counters[0]), uintptr(n), &ctr.c.encKeys, &ctr.c.simdSbox)
		subtle.XORBytes(dst[done:done+n], src[done:done+n], gamma[:n])
		done += n
	}
	return done
}

func hasAVX2() bool {
	_, _, ecx, _ := cpuid(1, 0)
	const osxsaveAVX = (1 << 27) | (1 << 28)
	if ecx&osxsaveAVX != osxsaveAVX {
		return false
	}
	xcr0Lo, _ := xgetbv(0)
	if xcr0Lo&0x06 != 0x06 {
		return false
	}
	_, ebx, _, _ := cpuid(7, 0)
	return ebx&(1<<5) != 0
}
