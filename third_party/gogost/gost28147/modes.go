package gost28147

import "crypto/hmac"

// EncryptCBC шифрует block-aligned src по семантике CBC из ГОСТ Р 34.13.
func (c *Cipher) EncryptCBC(dst, src, iv []byte) {
	if len(src)%BlockSize != 0 {
		panic("gogost/gost28147: вход не кратен размеру блока")
	}
	if len(dst) < len(src) {
		panic("gogost/gost28147: выходной буфер слишком короткий")
	}
	if len(iv) != BlockSize {
		panic("gogost/gost28147: Некорректный размер IV")
	}
	prev := load64LE(iv)
	for len(src) >= BlockSize {
		block := load64LE(src[:BlockSize]) ^ prev
		prev = c.encryptBlock64(block)
		store64LE(dst[:BlockSize], prev)
		dst = dst[BlockSize:]
		src = src[BlockSize:]
	}
}

// DecryptCBC расшифровывает block-aligned src по семантике CBC из ГОСТ Р 34.13.
func (c *Cipher) DecryptCBC(dst, src, iv []byte) {
	if len(src)%BlockSize != 0 {
		panic("gogost/gost28147: вход не кратен размеру блока")
	}
	if len(dst) < len(src) {
		panic("gogost/gost28147: выходной буфер слишком короткий")
	}
	if len(iv) != BlockSize {
		panic("gogost/gost28147: Некорректный размер IV")
	}
	prev := load64LE(iv)
	for len(src) >= BlockSize {
		ct := load64LE(src[:BlockSize])
		pt := c.decryptBlock64(ct) ^ prev
		store64LE(dst[:BlockSize], pt)
		prev = ct
		dst = dst[BlockSize:]
		src = src[BlockSize:]
	}
}

// EncryptCFB шифрует src по full-block семантике CFB из ГОСТ Р 34.13.
func (c *Cipher) EncryptCFB(dst, src, iv []byte) {
	if len(dst) < len(src) {
		panic("gogost/gost28147: выходной буфер слишком короткий")
	}
	if len(iv) != BlockSize {
		panic("gogost/gost28147: Некорректный размер IV")
	}
	reg := load64LE(iv)
	for len(src) >= BlockSize {
		ct := load64LE(src[:BlockSize]) ^ c.encryptBlock64(reg)
		store64LE(dst[:BlockSize], ct)
		reg = ct
		dst = dst[BlockSize:]
		src = src[BlockSize:]
	}
	if len(src) > 0 {
		var gamma [BlockSize]byte
		store64LE(gamma[:], c.encryptBlock64(reg))
		xorTail(dst, src, gamma[:])
	}
}

// DecryptCFB расшифровывает src по full-block семантике CFB из ГОСТ Р 34.13.
func (c *Cipher) DecryptCFB(dst, src, iv []byte) {
	if len(dst) < len(src) {
		panic("gogost/gost28147: выходной буфер слишком короткий")
	}
	if len(iv) != BlockSize {
		panic("gogost/gost28147: Некорректный размер IV")
	}
	reg := load64LE(iv)
	for len(src) >= BlockSize {
		ct := load64LE(src[:BlockSize])
		pt := ct ^ c.encryptBlock64(reg)
		store64LE(dst[:BlockSize], pt)
		reg = ct
		dst = dst[BlockSize:]
		src = src[BlockSize:]
	}
	if len(src) > 0 {
		var gamma [BlockSize]byte
		store64LE(gamma[:], c.encryptBlock64(reg))
		xorTail(dst, src, gamma[:])
	}
}

// XORKeyStreamOFB применяет XOR src с full-block OFB stream из ГОСТ Р 34.13.
func (c *Cipher) XORKeyStreamOFB(dst, src, iv []byte) {
	if len(dst) < len(src) {
		panic("gogost/gost28147: выходной буфер слишком короткий")
	}
	if len(iv) != BlockSize {
		panic("gogost/gost28147: Некорректный размер IV")
	}
	reg := load64LE(iv)
	for len(src) >= BlockSize {
		reg = c.encryptBlock64(reg)
		store64LE(dst[:BlockSize], load64LE(src[:BlockSize])^reg)
		dst = dst[BlockSize:]
		src = src[BlockSize:]
	}
	if len(src) > 0 {
		var gamma [BlockSize]byte
		reg = c.encryptBlock64(reg)
		store64LE(gamma[:], reg)
		xorTail(dst, src, gamma[:])
	}
}

// XORKeyStreamCTRCounter применяет XOR src с гаммой CTR из ГОСТ Р 34.13 и изменяет counter.
func (c *Cipher) XORKeyStreamCTRCounter(dst, src, counter []byte) {
	if len(dst) < len(src) {
		panic("gogost/gost28147: выходной буфер слишком короткий")
	}
	if len(counter) != BlockSize {
		panic("gogost/gost28147: Некорректный размер счётчика")
	}
	left := nv(load32LE(counter[0:4]))
	right := load32BE(counter[4:8])
	keys := &c.encKeys
	if n := xorKeyStreamGOST3413CTRSIMD(c, dst, src, counter); n > 0 {
		right = load32BE(counter[4:8])
		dst = dst[n:]
		src = src[n:]
	}
	if t16 := c.t16; t16 != nil {
		for len(src) >= 4*BlockSize {
			a1, a2 := left, nv(byteSwap32(right))
			b1, b2 := left, nv(byteSwap32(right+1))
			d1, d2 := left, nv(byteSwap32(right+2))
			e1, e2 := left, nv(byteSwap32(right+3))
			a1, a2, b1, b2, d1, d2, e1, e2 = xcrypt32x4T16(keys, t16, a1, a2, b1, b2, d1, d2, e1, e2)
			store32LE(dst[0:4], load32LE(src[0:4])^uint32(a2))
			store32LE(dst[4:8], load32LE(src[4:8])^uint32(a1))
			store32LE(dst[8:12], load32LE(src[8:12])^uint32(b2))
			store32LE(dst[12:16], load32LE(src[12:16])^uint32(b1))
			store32LE(dst[16:20], load32LE(src[16:20])^uint32(d2))
			store32LE(dst[20:24], load32LE(src[20:24])^uint32(d1))
			store32LE(dst[24:28], load32LE(src[24:28])^uint32(e2))
			store32LE(dst[28:32], load32LE(src[28:32])^uint32(e1))
			right += 4
			dst = dst[4*BlockSize:]
			src = src[4*BlockSize:]
		}
		for len(src) >= 2*BlockSize {
			a1, a2 := left, nv(byteSwap32(right))
			b1, b2 := left, nv(byteSwap32(right+1))
			a1, a2, b1, b2 = xcrypt32x2T16(keys, t16, a1, a2, b1, b2)
			store32LE(dst[0:4], load32LE(src[0:4])^uint32(a2))
			store32LE(dst[4:8], load32LE(src[4:8])^uint32(a1))
			store32LE(dst[8:12], load32LE(src[8:12])^uint32(b2))
			store32LE(dst[12:16], load32LE(src[12:16])^uint32(b1))
			right += 2
			dst = dst[2*BlockSize:]
			src = src[2*BlockSize:]
		}
		for len(src) >= BlockSize {
			n1, n2 := xcrypt32T16(keys, t16, left, nv(byteSwap32(right)))
			store32LE(dst[0:4], load32LE(src[0:4])^uint32(n2))
			store32LE(dst[4:8], load32LE(src[4:8])^uint32(n1))
			right++
			dst = dst[BlockSize:]
			src = src[BlockSize:]
		}
		if len(src) > 0 {
			n1, n2 := xcrypt32T16(keys, t16, left, nv(byteSwap32(right)))
			var gamma [BlockSize]byte
			nvs2block(n1, n2, gamma[:])
			xorTail(dst, src, gamma[:])
			right++
		}
		store32BE(counter[4:8], right)
		return
	}
	for len(src) >= BlockSize {
		n1, n2 := xcrypt32(keys, c.table, left, nv(byteSwap32(right)))
		gamma := uint64(uint32(n2)) | uint64(uint32(n1))<<32
		store64LE(dst[:BlockSize], load64LE(src[:BlockSize])^gamma)
		right++
		dst = dst[BlockSize:]
		src = src[BlockSize:]
	}
	if len(src) > 0 {
		var gamma [BlockSize]byte
		n1, n2 := xcrypt32(keys, c.table, left, nv(byteSwap32(right)))
		nvs2block(n1, n2, gamma[:])
		xorTail(dst, src, gamma[:])
		right++
	}
	store32BE(counter[4:8], right)
}

// SumGOST3413MAC дописывает в dst MAC tag по ГОСТ Р 34.13.
func (c *Cipher) SumGOST3413MAC(dst, data []byte, tagSize int) []byte {
	if tagSize <= 0 || tagSize > BlockSize {
		panic("gogost/gost28147: Некорректный размер тега")
	}
	ret, out := appendTag(dst, tagSize)
	c.sumGOST3413MACInto(out, data, tagSize)
	return ret
}

// VerifyGOST3413MAC сообщает, является ли tag корректным MAC по ГОСТ Р 34.13.
func (c *Cipher) VerifyGOST3413MAC(data, tag []byte) bool {
	if len(tag) == 0 || len(tag) > BlockSize {
		return false
	}
	var expected [BlockSize]byte
	c.sumGOST3413MACInto(expected[:len(tag)], data, len(tag))
	return hmac.Equal(expected[:len(tag)], tag)
}

func (c *Cipher) sumGOST3413MACInto(out, data []byte, tagSize int) {
	var state uint64
	fullBlocks := len(data) / BlockSize
	var last uint64
	if len(data) > 0 && len(data)%BlockSize == 0 {
		fullBlocks--
		last = load64LE(data[len(data)-BlockSize:]) ^ c.gost3413MacK1u
	} else {
		var padded [BlockSize]byte
		copy(padded[:], data[fullBlocks*BlockSize:])
		padded[len(data)-fullBlocks*BlockSize] = 0x80
		last = load64LE(padded[:]) ^ c.gost3413MacK2u
	}
	for offset := 0; offset < fullBlocks*BlockSize; offset += BlockSize {
		state ^= load64LE(data[offset : offset+BlockSize])
		state = c.encryptBlock64(state)
	}
	state ^= last
	state = c.encryptBlock64(state)
	var tag [BlockSize]byte
	store64LE(tag[:], state)
	copy(out[:tagSize], tag[:tagSize])
}

func (c *Cipher) initGOST3413MACSubkeys() {
	l := c.encryptBlock64(0)
	var block [BlockSize]byte
	store64LE(block[:], l)
	doubleSubkey(c.gost3413MacK1[:], block[:])
	doubleSubkey(c.gost3413MacK2[:], c.gost3413MacK1[:])
	c.gost3413MacK1u = load64LE(c.gost3413MacK1[:])
	c.gost3413MacK2u = load64LE(c.gost3413MacK2[:])
}

func (c *Cipher) encryptBlock64(v uint64) uint64 {
	n1 := nv(uint32(v))
	n2 := nv(uint32(v >> 32))
	if t16 := c.t16; t16 != nil {
		n1, n2 = xcrypt32EncryptT16(&c.baseKeys, t16, n1, n2)
	} else {
		n1, n2 = xcrypt32Encrypt(&c.baseKeys, c.table, n1, n2)
	}
	return uint64(uint32(n2)) | uint64(uint32(n1))<<32
}

// CFB feedback has data-dependent table access even when ciphertext is
// available in advance. The compact table stays cache-resident on this path.
func (c *Cipher) encryptBlock64CFB(v uint64) uint64 {
	n1, n2 := xcrypt32Encrypt(&c.baseKeys, c.table, nv(uint32(v)), nv(uint32(v>>32)))
	return uint64(uint32(n2)) | uint64(uint32(n1))<<32
}

func (c *Cipher) decryptBlock64(v uint64) uint64 {
	n1 := nv(uint32(v))
	n2 := nv(uint32(v >> 32))
	if t16 := c.t16; t16 != nil {
		n1, n2 = xcrypt32DecryptT16(&c.baseKeys, t16, n1, n2)
	} else {
		n1, n2 = xcrypt32Decrypt(&c.baseKeys, c.table, n1, n2)
	}
	return uint64(uint32(n2)) | uint64(uint32(n1))<<32
}

func load64LE(b []byte) uint64 {
	_ = b[7]
	return uint64(load32LE(b[0:4])) | uint64(load32LE(b[4:8]))<<32
}

func store64LE(b []byte, v uint64) {
	_ = b[7]
	store32LE(b[0:4], uint32(v))
	store32LE(b[4:8], uint32(v>>32))
}

func load32BE(b []byte) uint32 {
	_ = b[3]
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func store32BE(b []byte, v uint32) {
	_ = b[3]
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}

func byteSwap32(v uint32) uint32 {
	return v<<24 | v>>24 | (v&0x0000ff00)<<8 | (v&0x00ff0000)>>8
}

func xorTail(dst, src, gamma []byte) {
	for i := range src {
		dst[i] = src[i] ^ gamma[i]
	}
}

func doubleSubkey(out, k []byte) {
	var carry byte
	for i := len(k) - 1; i >= 0; i-- {
		nextCarry := k[i] >> 7
		out[i] = (k[i] << 1) | carry
		carry = nextCarry
	}
	if carry != 0 {
		out[len(out)-1] ^= 0x1b
	}
}

func appendTag(dst []byte, n int) ([]byte, []byte) {
	if total := len(dst) + n; cap(dst) >= total {
		ret := dst[:total]
		return ret, ret[len(dst):]
	}
	ret := make([]byte, len(dst)+n)
	copy(ret, dst)
	return ret, ret[len(dst):]
}
