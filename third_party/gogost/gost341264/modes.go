package gost341264

import "crypto/hmac"

// EncryptCBC шифрует block-aligned src по семантике CBC из ГОСТ Р 34.13.
func (c *Cipher) EncryptCBC(dst, src, iv []byte) {
	if len(src)%BlockSize != 0 {
		panic("gogost/gost341264: вход не кратен размеру блока")
	}
	if len(dst) < len(src) {
		panic("gogost/gost341264: dst слишком короткий")
	}
	if len(iv) != BlockSize {
		panic("gogost/gost341264: Некорректный размер IV")
	}
	prev := load64BE(iv)
	for len(src) >= BlockSize {
		block := load64BE(src[:BlockSize]) ^ prev
		prev = c.encryptBlock64(block)
		store64BE(dst[:BlockSize], prev)
		dst = dst[BlockSize:]
		src = src[BlockSize:]
	}
}

// DecryptCBC расшифровывает block-aligned src по семантике CBC из ГОСТ Р 34.13.
func (c *Cipher) DecryptCBC(dst, src, iv []byte) {
	if len(src)%BlockSize != 0 {
		panic("gogost/gost341264: вход не кратен размеру блока")
	}
	if len(dst) < len(src) {
		panic("gogost/gost341264: dst слишком короткий")
	}
	if len(iv) != BlockSize {
		panic("gogost/gost341264: Некорректный размер IV")
	}
	prev := load64BE(iv)
	for len(src) >= BlockSize {
		ct := load64BE(src[:BlockSize])
		pt := c.decryptBlock64(ct) ^ prev
		store64BE(dst[:BlockSize], pt)
		prev = ct
		dst = dst[BlockSize:]
		src = src[BlockSize:]
	}
}

// EncryptCFB шифрует src по full-block семантике CFB из ГОСТ Р 34.13.
func (c *Cipher) EncryptCFB(dst, src, iv []byte) {
	if len(dst) < len(src) {
		panic("gogost/gost341264: dst слишком короткий")
	}
	if len(iv) != BlockSize {
		panic("gogost/gost341264: Некорректный размер IV")
	}
	reg := load64BE(iv)
	for len(src) >= BlockSize {
		ct := load64BE(src[:BlockSize]) ^ c.encryptBlock64(reg)
		store64BE(dst[:BlockSize], ct)
		reg = ct
		dst = dst[BlockSize:]
		src = src[BlockSize:]
	}
	if len(src) > 0 {
		var gamma [BlockSize]byte
		store64BE(gamma[:], c.encryptBlock64(reg))
		xorTail(dst, src, gamma[:])
	}
}

// DecryptCFB расшифровывает src по full-block семантике CFB из ГОСТ Р 34.13.
func (c *Cipher) DecryptCFB(dst, src, iv []byte) {
	if len(dst) < len(src) {
		panic("gogost/gost341264: dst слишком короткий")
	}
	if len(iv) != BlockSize {
		panic("gogost/gost341264: Некорректный размер IV")
	}
	reg := load64BE(iv)
	for len(src) >= BlockSize {
		ct := load64BE(src[:BlockSize])
		pt := ct ^ c.encryptBlock64(reg)
		store64BE(dst[:BlockSize], pt)
		reg = ct
		dst = dst[BlockSize:]
		src = src[BlockSize:]
	}
	if len(src) > 0 {
		var gamma [BlockSize]byte
		store64BE(gamma[:], c.encryptBlock64(reg))
		xorTail(dst, src, gamma[:])
	}
}

// XORKeyStreamOFB применяет XOR src с full-block OFB stream из ГОСТ Р 34.13.
func (c *Cipher) XORKeyStreamOFB(dst, src, iv []byte) {
	if len(dst) < len(src) {
		panic("gogost/gost341264: dst слишком короткий")
	}
	if len(iv) != BlockSize {
		panic("gogost/gost341264: Некорректный размер IV")
	}
	reg := load64BE(iv)
	for len(src) >= BlockSize {
		reg = c.encryptBlock64(reg)
		store64BE(dst[:BlockSize], load64BE(src[:BlockSize])^reg)
		dst = dst[BlockSize:]
		src = src[BlockSize:]
	}
	if len(src) > 0 {
		var gamma [BlockSize]byte
		reg = c.encryptBlock64(reg)
		store64BE(gamma[:], reg)
		xorTail(dst, src, gamma[:])
	}
}

// SumGOST3413MAC дописывает в dst MAC tag по ГОСТ Р 34.13.
func (c *Cipher) SumGOST3413MAC(dst, data []byte, tagSize int) []byte {
	if tagSize <= 0 || tagSize > BlockSize {
		panic("gogost/gost341264: Некорректный размер тега")
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
		last = load64BE(data[len(data)-BlockSize:]) ^ c.macK1u64
	} else {
		var padded [BlockSize]byte
		copy(padded[:], data[fullBlocks*BlockSize:])
		padded[len(data)-fullBlocks*BlockSize] = 0x80
		last = load64BE(padded[:]) ^ c.macK2u64
	}
	for offset := 0; offset < fullBlocks*BlockSize; offset += BlockSize {
		state ^= load64BE(data[offset : offset+BlockSize])
		state = c.encryptBlock64(state)
	}
	state ^= last
	state = c.encryptBlock64(state)
	var tag [BlockSize]byte
	store64BE(tag[:], state)
	copy(out[:tagSize], tag[:tagSize])
}

func (c *Cipher) initMACSubkeys() {
	l := c.encryptBlock64(0)
	var block [BlockSize]byte
	store64BE(block[:], l)
	doubleSubkey(c.macK1[:], block[:])
	doubleSubkey(c.macK2[:], c.macK1[:])
	c.macK1u64 = load64BE(c.macK1[:])
	c.macK2u64 = load64BE(c.macK2[:])
}

func load64BE(b []byte) uint64 {
	_ = b[7]
	return uint64(b[0])<<56 |
		uint64(b[1])<<48 |
		uint64(b[2])<<40 |
		uint64(b[3])<<32 |
		uint64(b[4])<<24 |
		uint64(b[5])<<16 |
		uint64(b[6])<<8 |
		uint64(b[7])
}

func store64BE(b []byte, v uint64) {
	_ = b[7]
	b[0] = byte(v >> 56)
	b[1] = byte(v >> 48)
	b[2] = byte(v >> 40)
	b[3] = byte(v >> 32)
	b[4] = byte(v >> 24)
	b[5] = byte(v >> 16)
	b[6] = byte(v >> 8)
	b[7] = byte(v)
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
