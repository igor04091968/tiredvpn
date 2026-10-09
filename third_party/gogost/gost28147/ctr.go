package gost28147

type CTR struct {
	c  *Cipher
	n1 nv
	n2 nv
}

func (c *Cipher) NewCTR(iv []byte) *CTR {
	if len(iv) != BlockSize {
		panic("gogost/gost28147: длина IV не равна размеру блока")
	}
	n1, n2 := block2nvs(iv)
	if t16 := c.t16; t16 != nil {
		n2, n1 = xcrypt32EncryptT16(&c.baseKeys, t16, n1, n2)
	} else {
		n2, n1 = xcrypt32Encrypt(&c.baseKeys, c.table, n1, n2)
	}
	return &CTR{c, n1, n2}
}

func (c *Cipher) NewCTRValue(iv []byte) CTR {
	if len(iv) != BlockSize {
		panic("gogost/gost28147: длина IV должна быть равна размеру блока")
	}
	n1, n2 := block2nvs(iv)
	if t16 := c.t16; t16 != nil {
		n2, n1 = xcrypt32EncryptT16(&c.baseKeys, t16, n1, n2)
	} else {
		n2, n1 = xcrypt32Encrypt(&c.baseKeys, c.table, n1, n2)
	}
	return CTR{c, n1, n2}
}

func (c *Cipher) XORKeyStreamCTR(dst, src, iv []byte) {
	ctr := c.NewCTRValue(iv)
	ctr.XORKeyStream(dst, src)
}

func (ctr *CTR) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("gogost/gost28147: dst слишком короткий")
	}
	keys := &ctr.c.encKeys
	table := ctr.c.table

	if n := xorKeyStreamCTRSIMD(ctr, dst, src); n > 0 {
		dst = dst[n:]
		src = src[n:]
	}

	if t16 := ctr.c.t16; t16 != nil {
		for len(src) >= 4*BlockSize {
			ctr.n1 += 0x01010101 // C2
			ctr.n2 += 0x01010104 // C1
			if ctr.n2 >= (1<<32)-1 {
				ctr.n2 -= (1 << 32) - 1
			}
			a1, a2 := ctr.n1, ctr.n2

			ctr.n1 += 0x01010101
			ctr.n2 += 0x01010104
			if ctr.n2 >= (1<<32)-1 {
				ctr.n2 -= (1 << 32) - 1
			}
			b1, b2 := ctr.n1, ctr.n2

			ctr.n1 += 0x01010101
			ctr.n2 += 0x01010104
			if ctr.n2 >= (1<<32)-1 {
				ctr.n2 -= (1 << 32) - 1
			}
			c1, c2 := ctr.n1, ctr.n2

			ctr.n1 += 0x01010101
			ctr.n2 += 0x01010104
			if ctr.n2 >= (1<<32)-1 {
				ctr.n2 -= (1 << 32) - 1
			}
			d1, d2 := ctr.n1, ctr.n2

			a1, a2, b1, b2, c1, c2, d1, d2 = xcrypt32x4T16(keys, t16, a1, a2, b1, b2, c1, c2, d1, d2)
			store32LE(dst[0:4], load32LE(src[0:4])^uint32(a2))
			store32LE(dst[4:8], load32LE(src[4:8])^uint32(a1))
			store32LE(dst[8:12], load32LE(src[8:12])^uint32(b2))
			store32LE(dst[12:16], load32LE(src[12:16])^uint32(b1))
			store32LE(dst[16:20], load32LE(src[16:20])^uint32(c2))
			store32LE(dst[20:24], load32LE(src[20:24])^uint32(c1))
			store32LE(dst[24:28], load32LE(src[24:28])^uint32(d2))
			store32LE(dst[28:32], load32LE(src[28:32])^uint32(d1))

			dst = dst[4*BlockSize:]
			src = src[4*BlockSize:]
		}

		for len(src) >= 2*BlockSize {
			ctr.n1 += 0x01010101
			ctr.n2 += 0x01010104
			if ctr.n2 >= (1<<32)-1 {
				ctr.n2 -= (1 << 32) - 1
			}
			a1, a2 := ctr.n1, ctr.n2

			ctr.n1 += 0x01010101
			ctr.n2 += 0x01010104
			if ctr.n2 >= (1<<32)-1 {
				ctr.n2 -= (1 << 32) - 1
			}
			b1, b2 := ctr.n1, ctr.n2

			a1, a2, b1, b2 = xcrypt32x2T16(keys, t16, a1, a2, b1, b2)
			store32LE(dst[0:4], load32LE(src[0:4])^uint32(a2))
			store32LE(dst[4:8], load32LE(src[4:8])^uint32(a1))
			store32LE(dst[8:12], load32LE(src[8:12])^uint32(b2))
			store32LE(dst[12:16], load32LE(src[12:16])^uint32(b1))

			dst = dst[2*BlockSize:]
			src = src[2*BlockSize:]
		}

		for len(src) >= BlockSize {
			ctr.n1 += 0x01010101
			ctr.n2 += 0x01010104
			if ctr.n2 >= (1<<32)-1 {
				ctr.n2 -= (1 << 32) - 1
			}

			n1t, n2t := xcrypt32EncryptT16(&ctr.c.baseKeys, t16, ctr.n1, ctr.n2)
			store32LE(dst[0:4], load32LE(src[0:4])^uint32(n2t))
			store32LE(dst[4:8], load32LE(src[4:8])^uint32(n1t))

			dst = dst[BlockSize:]
			src = src[BlockSize:]
		}

		if len(src) > 0 {
			ctr.n1 += 0x01010101
			ctr.n2 += 0x01010104
			if ctr.n2 >= (1<<32)-1 {
				ctr.n2 -= (1 << 32) - 1
			}

			n1t, n2t := xcrypt32EncryptT16(&ctr.c.baseKeys, t16, ctr.n1, ctr.n2)
			var block [BlockSize]byte
			nvs2block(n1t, n2t, block[:])
			for i := range src {
				dst[i] = src[i] ^ block[i]
			}
		}
		return
	}

	for len(src) >= 4*BlockSize {
		ctr.n1 += 0x01010101 // C2
		ctr.n2 += 0x01010104 // C1
		if ctr.n2 >= (1<<32)-1 {
			ctr.n2 -= (1 << 32) - 1
		}
		a1, a2 := ctr.n1, ctr.n2

		ctr.n1 += 0x01010101
		ctr.n2 += 0x01010104
		if ctr.n2 >= (1<<32)-1 {
			ctr.n2 -= (1 << 32) - 1
		}
		b1, b2 := ctr.n1, ctr.n2

		ctr.n1 += 0x01010101
		ctr.n2 += 0x01010104
		if ctr.n2 >= (1<<32)-1 {
			ctr.n2 -= (1 << 32) - 1
		}
		c1, c2 := ctr.n1, ctr.n2

		ctr.n1 += 0x01010101
		ctr.n2 += 0x01010104
		if ctr.n2 >= (1<<32)-1 {
			ctr.n2 -= (1 << 32) - 1
		}
		d1, d2 := ctr.n1, ctr.n2

		for i := 0; i < 32; i++ {
			k := keys[i]
			a1, a2 = sboxLookup(table, a1+k)^a2, a1
			b1, b2 = sboxLookup(table, b1+k)^b2, b1
			c1, c2 = sboxLookup(table, c1+k)^c2, c1
			d1, d2 = sboxLookup(table, d1+k)^d2, d1
		}

		store32LE(dst[0:4], load32LE(src[0:4])^uint32(a2))
		store32LE(dst[4:8], load32LE(src[4:8])^uint32(a1))
		store32LE(dst[8:12], load32LE(src[8:12])^uint32(b2))
		store32LE(dst[12:16], load32LE(src[12:16])^uint32(b1))
		store32LE(dst[16:20], load32LE(src[16:20])^uint32(c2))
		store32LE(dst[20:24], load32LE(src[20:24])^uint32(c1))
		store32LE(dst[24:28], load32LE(src[24:28])^uint32(d2))
		store32LE(dst[28:32], load32LE(src[28:32])^uint32(d1))

		dst = dst[4*BlockSize:]
		src = src[4*BlockSize:]
	}

	for len(src) >= 2*BlockSize {
		ctr.n1 += 0x01010101
		ctr.n2 += 0x01010104
		if ctr.n2 >= (1<<32)-1 {
			ctr.n2 -= (1 << 32) - 1
		}
		a1, a2 := ctr.n1, ctr.n2

		ctr.n1 += 0x01010101
		ctr.n2 += 0x01010104
		if ctr.n2 >= (1<<32)-1 {
			ctr.n2 -= (1 << 32) - 1
		}
		b1, b2 := ctr.n1, ctr.n2

		a1, a2, b1, b2 = xcrypt32x2(keys, table, a1, a2, b1, b2)
		store32LE(dst[0:4], load32LE(src[0:4])^uint32(a2))
		store32LE(dst[4:8], load32LE(src[4:8])^uint32(a1))
		store32LE(dst[8:12], load32LE(src[8:12])^uint32(b2))
		store32LE(dst[12:16], load32LE(src[12:16])^uint32(b1))

		dst = dst[2*BlockSize:]
		src = src[2*BlockSize:]
	}

	for len(src) >= BlockSize {
		ctr.n1 += 0x01010101
		ctr.n2 += 0x01010104
		if ctr.n2 >= (1<<32)-1 {
			ctr.n2 -= (1 << 32) - 1
		}

		n1t, n2t := xcrypt32Encrypt(&ctr.c.baseKeys, table, ctr.n1, ctr.n2)
		store32LE(dst[0:4], load32LE(src[0:4])^uint32(n2t))
		store32LE(dst[4:8], load32LE(src[4:8])^uint32(n1t))

		dst = dst[BlockSize:]
		src = src[BlockSize:]
	}

	if len(src) > 0 {
		ctr.n1 += 0x01010101
		ctr.n2 += 0x01010104
		if ctr.n2 >= (1<<32)-1 {
			ctr.n2 -= (1 << 32) - 1
		}

		n1t, n2t := xcrypt32Encrypt(&ctr.c.baseKeys, table, ctr.n1, ctr.n2)
		var block [BlockSize]byte
		nvs2block(n1t, n2t, block[:])
		for i := range src {
			dst[i] = src[i] ^ block[i]
		}
	}
}
