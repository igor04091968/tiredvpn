package gost3412128

import "crypto/hmac"

// EncryptBlocks шифрует block-aligned src.
func (c *Cipher) EncryptBlocks(dst, src []byte) {
	if len(src)%BlockSize != 0 {
		panic("gogost/gost3412128: вход не кратен размеру блока")
	}
	if len(dst) < len(src) {
		panic("gogost/gost3412128: выходной буфер слишком короткий")
	}
	if n := encryptBlocksBackend(dst, src, &c.ks); n > 0 {
		dst = dst[n:]
		src = src[n:]
	}
	for len(src) >= 4*BlockSize {
		encryptBlock(
			(*[BlockSize]byte)(dst[:BlockSize]),
			(*[BlockSize]byte)(src[:BlockSize]),
			&c.ks,
		)
		encryptBlock(
			(*[BlockSize]byte)(dst[BlockSize:2*BlockSize]),
			(*[BlockSize]byte)(src[BlockSize:2*BlockSize]),
			&c.ks,
		)
		encryptBlock(
			(*[BlockSize]byte)(dst[2*BlockSize:3*BlockSize]),
			(*[BlockSize]byte)(src[2*BlockSize:3*BlockSize]),
			&c.ks,
		)
		encryptBlock(
			(*[BlockSize]byte)(dst[3*BlockSize:4*BlockSize]),
			(*[BlockSize]byte)(src[3*BlockSize:4*BlockSize]),
			&c.ks,
		)
		dst = dst[4*BlockSize:]
		src = src[4*BlockSize:]
	}
	for len(src) >= BlockSize {
		encryptBlock(
			(*[BlockSize]byte)(dst[:BlockSize]),
			(*[BlockSize]byte)(src[:BlockSize]),
			&c.ks,
		)
		dst = dst[BlockSize:]
		src = src[BlockSize:]
	}
}

// EncryptBlocksCompact encrypts block-aligned src using the batching backend
// with the smallest working set available on the current CPU. It is intended
// for callers, such as authenticated modes, whose hot data must remain in the
// cache. For short inputs and unsupported architectures it is equivalent to
// EncryptBlocks.
func (c *Cipher) EncryptBlocksCompact(dst, src []byte) {
	if len(src)%BlockSize != 0 {
		panic("gogost/gost3412128: input is not a whole number of blocks")
	}
	if len(dst) < len(src) {
		panic("gogost/gost3412128: output buffer is too short")
	}
	if n := encryptBlocksCompactBackend(dst, src, &c.ks); n > 0 {
		dst = dst[n:]
		src = src[n:]
	}
	for len(src) >= BlockSize {
		encryptBlock(
			(*[BlockSize]byte)(dst[:BlockSize]),
			(*[BlockSize]byte)(src[:BlockSize]),
			&c.ks,
		)
		dst = dst[BlockSize:]
		src = src[BlockSize:]
	}
}

// DecryptBlocks расшифровывает block-aligned src.
func (c *Cipher) DecryptBlocks(dst, src []byte) {
	if len(src)%BlockSize != 0 {
		panic("gogost/gost3412128: вход не кратен размеру блока")
	}
	if len(dst) < len(src) {
		panic("gogost/gost3412128: выходной буфер слишком короткий")
	}
	if n := decryptBlocksBackend(dst, src, &c.decKs); n > 0 {
		dst = dst[n:]
		src = src[n:]
	}
	for len(src) >= 4*BlockSize {
		decryptBlock(
			(*[BlockSize]byte)(dst[:BlockSize]),
			(*[BlockSize]byte)(src[:BlockSize]),
			&c.decKs,
		)
		decryptBlock(
			(*[BlockSize]byte)(dst[BlockSize:2*BlockSize]),
			(*[BlockSize]byte)(src[BlockSize:2*BlockSize]),
			&c.decKs,
		)
		decryptBlock(
			(*[BlockSize]byte)(dst[2*BlockSize:3*BlockSize]),
			(*[BlockSize]byte)(src[2*BlockSize:3*BlockSize]),
			&c.decKs,
		)
		decryptBlock(
			(*[BlockSize]byte)(dst[3*BlockSize:4*BlockSize]),
			(*[BlockSize]byte)(src[3*BlockSize:4*BlockSize]),
			&c.decKs,
		)
		dst = dst[4*BlockSize:]
		src = src[4*BlockSize:]
	}
	for len(src) >= BlockSize {
		decryptBlock(
			(*[BlockSize]byte)(dst[:BlockSize]),
			(*[BlockSize]byte)(src[:BlockSize]),
			&c.decKs,
		)
		dst = dst[BlockSize:]
		src = src[BlockSize:]
	}
}

// EncryptCBC шифрует block-aligned src по семантике CBC из ГОСТ Р 34.13.
func (c *Cipher) EncryptCBC(dst, src, iv []byte) {
	if len(src)%BlockSize != 0 {
		panic("gogost/gost3412128: вход не кратен размеру блока")
	}
	if len(dst) < len(src) {
		panic("gogost/gost3412128: выходной буфер слишком короткий")
	}
	if len(iv) != BlockSize {
		panic("gogost/gost3412128: Некорректный размер IV")
	}
	var block, prev [BlockSize]byte
	copy(prev[:], iv)
	for len(src) >= BlockSize {
		xorSliceIntoBlock(&block, src[:BlockSize], prev[:])
		encryptBlock((*[BlockSize]byte)(dst[:BlockSize]), &block, &c.ks)
		copy(prev[:], dst[:BlockSize])
		dst = dst[BlockSize:]
		src = src[BlockSize:]
	}
}

// DecryptCBC расшифровывает block-aligned src по семантике CBC из ГОСТ Р 34.13.
func (c *Cipher) DecryptCBC(dst, src, iv []byte) {
	if len(src)%BlockSize != 0 {
		panic("gogost/gost3412128: вход не кратен размеру блока")
	}
	if len(dst) < len(src) {
		panic("gogost/gost3412128: выходной буфер слишком короткий")
	}
	if len(iv) != BlockSize {
		panic("gogost/gost3412128: Некорректный размер IV")
	}
	var block, prev, ct [BlockSize]byte
	copy(prev[:], iv)
	for len(src) >= BlockSize {
		copy(ct[:], src[:BlockSize])
		decryptBlock(&block, &ct, &c.decKs)
		xorBlockInPlace(&block, &prev)
		copy(dst[:BlockSize], block[:])
		prev = ct
		dst = dst[BlockSize:]
		src = src[BlockSize:]
	}
}

// EncryptCFB шифрует src по full-block семантике CFB из ГОСТ Р 34.13.
func (c *Cipher) EncryptCFB(dst, src, iv []byte) {
	if len(dst) < len(src) {
		panic("gogost/gost3412128: выходной буфер слишком короткий")
	}
	if len(iv) != BlockSize {
		panic("gogost/gost3412128: Некорректный размер IV")
	}
	var reg, gamma, block [BlockSize]byte
	copy(reg[:], iv)
	for len(src) >= BlockSize {
		encryptBlock(&gamma, &reg, &c.ks)
		xorSliceIntoBlock(&block, src[:BlockSize], gamma[:])
		copy(dst[:BlockSize], block[:])
		reg = block
		dst = dst[BlockSize:]
		src = src[BlockSize:]
	}
	if len(src) > 0 {
		encryptBlock(&gamma, &reg, &c.ks)
		xorTail(dst, src, gamma[:])
	}
}

// DecryptCFB расшифровывает src по full-block семантике CFB из ГОСТ Р 34.13.
func (c *Cipher) DecryptCFB(dst, src, iv []byte) {
	if len(dst) < len(src) {
		panic("gogost/gost3412128: выходной буфер слишком короткий")
	}
	if len(iv) != BlockSize {
		panic("gogost/gost3412128: Некорректный размер IV")
	}
	var reg, gamma, ct [BlockSize]byte
	copy(reg[:], iv)
	for len(src) >= BlockSize {
		copy(ct[:], src[:BlockSize])
		encryptBlock(&gamma, &reg, &c.ks)
		xorSliceIntoBlock((*[BlockSize]byte)(dst[:BlockSize]), src[:BlockSize], gamma[:])
		reg = ct
		dst = dst[BlockSize:]
		src = src[BlockSize:]
	}
	if len(src) > 0 {
		encryptBlock(&gamma, &reg, &c.ks)
		xorTail(dst, src, gamma[:])
	}
}

// XORKeyStreamOFB применяет XOR src с full-block OFB stream из ГОСТ Р 34.13.
func (c *Cipher) XORKeyStreamOFB(dst, src, iv []byte) {
	if len(dst) < len(src) {
		panic("gogost/gost3412128: выходной буфер слишком короткий")
	}
	if len(iv) != BlockSize {
		panic("gogost/gost3412128: Некорректный размер IV")
	}
	var reg, gamma [BlockSize]byte
	copy(reg[:], iv)
	for len(src) >= BlockSize {
		encryptBlock(&gamma, &reg, &c.ks)
		xorSliceIntoBlock((*[BlockSize]byte)(dst[:BlockSize]), src[:BlockSize], gamma[:])
		reg = gamma
		dst = dst[BlockSize:]
		src = src[BlockSize:]
	}
	if len(src) > 0 {
		encryptBlock(&gamma, &reg, &c.ks)
		xorTail(dst, src, gamma[:])
	}
}

// XORKeyStreamCTRCounter применяет XOR src с гаммой CTR из ГОСТ Р 34.13 и изменяет counter.
func (c *Cipher) XORKeyStreamCTRCounter(dst, src, counter []byte) {
	if len(dst) < len(src) {
		panic("gogost/gost3412128: выходной буфер слишком короткий")
	}
	if len(counter) != BlockSize {
		panic("gogost/gost3412128: Некорректный размер счётчика")
	}
	xorKeyStreamCTRCounterBackend(dst, src, (*[BlockSize]byte)(counter[:BlockSize]), &c.ks)
}

func xorKeyStreamCTRCounterGeneric(dst, src []byte, counter *[BlockSize]byte, rkeys *[10][BlockSize]byte) {
	var gamma [BlockSize]byte
	for len(src) >= BlockSize {
		encryptBlock(&gamma, counter, rkeys)
		xorSliceIntoBlock((*[BlockSize]byte)(dst[:BlockSize]), src[:BlockSize], gamma[:])
		incCounterHalf(counter[BlockSize/2:])
		dst = dst[BlockSize:]
		src = src[BlockSize:]
	}
	if len(src) > 0 {
		encryptBlock(&gamma, counter, rkeys)
		xorTail(dst, src, gamma[:])
		incCounterHalf(counter[BlockSize/2:])
	}
}

// SumGOST3413MAC дописывает в dst MAC tag по ГОСТ Р 34.13.
func (c *Cipher) SumGOST3413MAC(dst, data []byte, tagSize int) []byte {
	if tagSize <= 0 || tagSize > BlockSize {
		panic("gogost/gost3412128: Некорректный размер тега")
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
	var state, last [BlockSize]byte
	fullBlocks := len(data) / BlockSize
	if len(data) > 0 && len(data)%BlockSize == 0 {
		fullBlocks--
		xorSliceIntoBlock(&last, data[len(data)-BlockSize:], c.macK1[:])
	} else {
		var padded [BlockSize]byte
		copy(padded[:], data[fullBlocks*BlockSize:])
		padded[len(data)-fullBlocks*BlockSize] = 0x80
		xorSliceIntoBlock(&last, padded[:], c.macK2[:])
	}
	for offset := 0; offset < fullBlocks*BlockSize; offset += BlockSize {
		xorSliceIntoBlock(&state, state[:], data[offset:offset+BlockSize])
		encryptBlock(&state, &state, &c.ks)
	}
	xorBlockInPlace(&state, &last)
	encryptBlock(&state, &state, &c.ks)
	copy(out[:tagSize], state[:tagSize])
}

func (c *Cipher) initMACSubkeys() {
	var zero, l [BlockSize]byte
	encryptBlock(&l, &zero, &c.ks)
	doubleSubkey(c.macK1[:], l[:])
	doubleSubkey(c.macK2[:], c.macK1[:])
}

func xorSliceIntoBlock(dst *[BlockSize]byte, a, b []byte) {
	alo, ahi := getBlock64((*[BlockSize]byte)(a[:BlockSize]))
	blo, bhi := getBlock64((*[BlockSize]byte)(b[:BlockSize]))
	putBlock64(dst, alo^blo, ahi^bhi)
}

func xorTail(dst, src, gamma []byte) {
	for i := range src {
		dst[i] = src[i] ^ gamma[i]
	}
}

func incCounterHalf(counter []byte) {
	for i := len(counter) - 1; i >= 0; i-- {
		counter[i]++
		if counter[i] != 0 {
			return
		}
	}
}

func addCounterHalf(counter []byte, blocks int) {
	carry := blocks
	for i := len(counter) - 1; i >= 0 && carry != 0; i-- {
		sum := int(counter[i]) + carry
		counter[i] = byte(sum)
		carry = sum >> 8
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
		out[len(out)-1] ^= 0x87
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
