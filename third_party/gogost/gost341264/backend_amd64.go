//go:build amd64 && !purego

package gost341264

import "unsafe"

func cpuid(eaxArg, ecxArg uint32) (eax, ebx, ecx, edx uint32)
func xgetbv(index uint32) (eax, edx uint32)

//go:noescape
func cryptBlocksAVX2(dst, src unsafe.Pointer, n uintptr, keys *[32]word)

//go:noescape
func cryptBlocksAVX2x16(dst, src unsafe.Pointer, n uintptr, keys *[32]word)

//go:noescape
func xorKeyStreamCTRAVX2(dst, src unsafe.Pointer, n uintptr, keys *[32]word, left, right uint32) uint32

//go:noescape
func magmaCrypt32CompactEncrypt(keys *[8]word, table *[4][256]word, n1, n2 word) (ret1, ret2 word)

//go:noescape
func magmaCrypt32CompactDecrypt(keys *[8]word, table *[4][256]word, n1, n2 word) (ret1, ret2 word)

func (c *Cipher) encryptBlock64(v uint64) uint64 {
	n1, n2 := magmaCrypt32CompactEncrypt(&c.baseKeys, c.table, word(uint32(v)), word(uint32(v>>32)))
	return uint64(uint32(n1))<<32 | uint64(uint32(n2))
}

func (c *Cipher) decryptBlock64(v uint64) uint64 {
	n1, n2 := magmaCrypt32CompactDecrypt(&c.baseKeys, c.table, word(uint32(v)), word(uint32(v>>32)))
	return uint64(uint32(n1))<<32 | uint64(uint32(n2))
}

var useAVX2 = hasAVX2()

var (
	magmaSIMDNibbleMask = [32]byte{
		0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f,
		0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f,
		0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f,
		0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f,
	}
	magmaSIMDPos0Mask = [32]byte{0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0}
	magmaSIMDPos1Mask = [32]byte{0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0}
	magmaSIMDPos2Mask = [32]byte{0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0}
	magmaSIMDPos3Mask = [32]byte{0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff}
	magmaCTRRightInc  = [8]uint32{0, 1, 2, 3, 4, 5, 6, 7}
	magmaByteSwap32   = [32]byte{3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12, 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12}
	magmaSIMDPermN1   = [8]uint32{1, 3, 5, 7, 0, 0, 0, 0}
	magmaSIMDPermN2   = [8]uint32{0, 2, 4, 6, 0, 0, 0, 0}
	magmaSIMDSbox     = [8][32]byte{
		{12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1, 12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1},
		{6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15, 6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15},
		{11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0, 11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0},
		{12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11, 12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11},
		{7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12, 7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12},
		{5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0, 5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0},
		{8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7, 8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7},
		{1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2, 1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2},
	}
)

func (c *Cipher) encryptBlock(dst, src []byte) {
	n1 := word(load32BE(src[4:8]))
	n2 := word(load32BE(src[0:4]))
	n1, n2 = magmaCrypt32EncryptT16(&c.baseKeys, c.t16, n1, n2)
	store32BE(dst[0:4], uint32(n1))
	store32BE(dst[4:8], uint32(n2))
}

func (c *Cipher) decryptBlock(dst, src []byte) {
	n1 := word(load32BE(src[4:8]))
	n2 := word(load32BE(src[0:4]))
	n1, n2 = magmaCrypt32DecryptT16(&c.baseKeys, c.t16, n1, n2)
	store32BE(dst[0:4], uint32(n1))
	store32BE(dst[4:8], uint32(n2))
}

const (
	encryptBlocksAVX2Min = 8 * BlockSize
	decryptBlocksAVX2Min = 8 * BlockSize
)

func encryptBlocksSIMD(dst, src []byte, keys *[32]word) int {
	return cryptBlocksSIMDMin(dst, src, keys, encryptBlocksAVX2Min)
}

func decryptBlocksSIMD(dst, src []byte, keys *[32]word) int {
	return cryptBlocksSIMDMin(dst, src, keys, decryptBlocksAVX2Min)
}

func cryptBlocksSIMDMin(dst, src []byte, keys *[32]word, min int) int {
	if !useAVX2 {
		return 0
	}
	done := 0
	if len(src) >= 16*BlockSize {
		n := len(src) &^ (16*BlockSize - 1)
		cryptBlocksAVX2x16(unsafe.Pointer(&dst[0]), unsafe.Pointer(&src[0]), uintptr(n), keys)
		done = n
		dst = dst[n:]
		src = src[n:]
	}
	if len(src) >= min {
		n := len(src) &^ (8*BlockSize - 1)
		cryptBlocksAVX2(unsafe.Pointer(&dst[0]), unsafe.Pointer(&src[0]), uintptr(n), keys)
		done += n
		dst = dst[n:]
		src = src[n:]
	}
	if len(src) >= 5*BlockSize {
		var in, out [8 * BlockSize]byte
		copy(in[:], src)
		cryptBlocksAVX2(unsafe.Pointer(&out[0]), unsafe.Pointer(&in[0]), uintptr(len(in)), keys)
		copy(dst, out[:len(src)])
		done += len(src)
	}
	return done
}

func xorKeyStreamCTRSIMD(c *Cipher, dst, src []byte, left, right uint32) (int, uint32) {
	if !useAVX2 || len(src) < 1024 {
		return 0, right
	}
	total := len(src) &^ (8*BlockSize - 1)
	right = xorKeyStreamCTRAVX2(unsafe.Pointer(&dst[0]), unsafe.Pointer(&src[0]), uintptr(total), &c.encKeys, left, right)
	return total, right
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
