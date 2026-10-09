// Package gost341264 реализует 64-битный блочный шифр Магма
// по ГОСТ Р 34.12-2015.
package gost341264

const (
	BlockSize = 8
	KeySize   = 32
)

type word uint32

type Cipher struct {
	baseKeys [8]word
	encKeys  [32]word
	decKeys  [32]word
	table    *[4][256]word
	t16      *magmaT16Table
	macK1    [BlockSize]byte
	macK2    [BlockSize]byte
	macK1u64 uint64
	macK2u64 uint64
}

var magmaSbox = [8][16]byte{
	{12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1},
	{6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15},
	{11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0},
	{12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11},
	{7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12},
	{5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0},
	{8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7},
	{1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2},
}

var magmaTable = makeMagmaTable()

var (
	magmaSeqEncrypt = [32]byte{
		0, 1, 2, 3, 4, 5, 6, 7,
		0, 1, 2, 3, 4, 5, 6, 7,
		0, 1, 2, 3, 4, 5, 6, 7,
		7, 6, 5, 4, 3, 2, 1, 0,
	}
	magmaSeqDecrypt = [32]byte{
		0, 1, 2, 3, 4, 5, 6, 7,
		7, 6, 5, 4, 3, 2, 1, 0,
		7, 6, 5, 4, 3, 2, 1, 0,
		7, 6, 5, 4, 3, 2, 1, 0,
	}
)

func NewCipher(key []byte) *Cipher {
	c := NewCipherValue(key)
	return &c
}

func NewCipherValue(key []byte) Cipher {
	var c Cipher
	c.SetKey(key)
	return c
}

func (c *Cipher) SetKey(key []byte) {
	if len(key) != KeySize {
		panic("gogost/gost341264: Некорректный размер ключа")
	}
	x := [8]word{
		word(load32BE(key[0:4])),
		word(load32BE(key[4:8])),
		word(load32BE(key[8:12])),
		word(load32BE(key[12:16])),
		word(load32BE(key[16:20])),
		word(load32BE(key[20:24])),
		word(load32BE(key[24:28])),
		word(load32BE(key[28:32])),
	}
	for i, idx := range magmaSeqEncrypt {
		c.encKeys[i] = x[idx]
	}
	for i, idx := range magmaSeqDecrypt {
		c.decKeys[i] = x[idx]
	}
	c.baseKeys = x
	c.table = &magmaTable
	c.t16 = magmaT16
	c.initMACSubkeys()
}

func (c *Cipher) BlockSize() int {
	return BlockSize
}

func (c *Cipher) Encrypt(dst, src []byte) {
	c.encryptBlock(dst, src)
}

func (c *Cipher) Decrypt(dst, src []byte) {
	c.decryptBlock(dst, src)
}

func (c *Cipher) EncryptBlocks(dst, src []byte) {
	if len(src) == BlockSize {
		if len(dst) < len(src) {
			panic("gogost/gost341264: dst слишком короткий")
		}
		c.Encrypt(dst, src)
		return
	}
	c.encryptBlocks(dst, src)
}

func (c *Cipher) DecryptBlocks(dst, src []byte) {
	if len(src) == BlockSize {
		if len(dst) < len(src) {
			panic("gogost/gost341264: dst слишком короткий")
		}
		c.Decrypt(dst, src)
		return
	}
	c.cryptBlocks(dst, src, &c.decKeys)
}

func (c *Cipher) cryptBlocks(dst, src []byte, keys *[32]word) {
	if len(src)%BlockSize != 0 {
		panic("gogost/gost341264: вход не кратен размеру блока")
	}
	if len(dst) < len(src) {
		panic("gogost/gost341264: dst слишком короткий")
	}
	if n := decryptBlocksSIMD(dst, src, keys); n > 0 {
		dst = dst[n:]
		src = src[n:]
	}
	t16 := c.t16
	for len(src) >= 4*BlockSize {
		a1, a2 := word(load32BE(src[4:8])), word(load32BE(src[0:4]))
		b1, b2 := word(load32BE(src[12:16])), word(load32BE(src[8:12]))
		c1, c2 := word(load32BE(src[20:24])), word(load32BE(src[16:20]))
		d1, d2 := word(load32BE(src[28:32])), word(load32BE(src[24:28]))
		a1, a2, b1, b2, c1, c2, d1, d2 = magmaCrypt32x4T16(keys, t16, a1, a2, b1, b2, c1, c2, d1, d2)
		store32BE(dst[0:4], uint32(a1))
		store32BE(dst[4:8], uint32(a2))
		store32BE(dst[8:12], uint32(b1))
		store32BE(dst[12:16], uint32(b2))
		store32BE(dst[16:20], uint32(c1))
		store32BE(dst[20:24], uint32(c2))
		store32BE(dst[24:28], uint32(d1))
		store32BE(dst[28:32], uint32(d2))
		dst = dst[4*BlockSize:]
		src = src[4*BlockSize:]
	}
	for len(src) >= 2*BlockSize {
		a1, a2 := word(load32BE(src[4:8])), word(load32BE(src[0:4]))
		b1, b2 := word(load32BE(src[12:16])), word(load32BE(src[8:12]))
		a1, a2, b1, b2 = magmaCrypt32x2T16(keys, t16, a1, a2, b1, b2)
		store32BE(dst[0:4], uint32(a1))
		store32BE(dst[4:8], uint32(a2))
		store32BE(dst[8:12], uint32(b1))
		store32BE(dst[12:16], uint32(b2))
		dst = dst[2*BlockSize:]
		src = src[2*BlockSize:]
	}
	for len(src) >= BlockSize {
		n1, n2 := magmaCrypt32T16(keys, t16, word(load32BE(src[4:8])), word(load32BE(src[0:4])))
		store32BE(dst[0:4], uint32(n1))
		store32BE(dst[4:8], uint32(n2))
		dst = dst[BlockSize:]
		src = src[BlockSize:]
	}
}

func (c *Cipher) encryptBlocks(dst, src []byte) {
	if len(src)%BlockSize != 0 {
		panic("gogost/gost341264: вход не кратен размеру блока")
	}
	if len(dst) < len(src) {
		panic("gogost/gost341264: dst слишком короткий")
	}
	if n := encryptBlocksSIMD(dst, src, &c.encKeys); n > 0 {
		dst = dst[n:]
		src = src[n:]
	}
	t16 := c.t16
	for len(src) >= 4*BlockSize {
		a1, a2 := word(load32BE(src[4:8])), word(load32BE(src[0:4]))
		b1, b2 := word(load32BE(src[12:16])), word(load32BE(src[8:12]))
		c1, c2 := word(load32BE(src[20:24])), word(load32BE(src[16:20]))
		d1, d2 := word(load32BE(src[28:32])), word(load32BE(src[24:28]))
		a1, a2, b1, b2, c1, c2, d1, d2 = magmaCrypt32x4T16(&c.encKeys, t16, a1, a2, b1, b2, c1, c2, d1, d2)
		store32BE(dst[0:4], uint32(a1))
		store32BE(dst[4:8], uint32(a2))
		store32BE(dst[8:12], uint32(b1))
		store32BE(dst[12:16], uint32(b2))
		store32BE(dst[16:20], uint32(c1))
		store32BE(dst[20:24], uint32(c2))
		store32BE(dst[24:28], uint32(d1))
		store32BE(dst[28:32], uint32(d2))
		dst = dst[4*BlockSize:]
		src = src[4*BlockSize:]
	}
	for len(src) >= 2*BlockSize {
		a1, a2 := word(load32BE(src[4:8])), word(load32BE(src[0:4]))
		b1, b2 := word(load32BE(src[12:16])), word(load32BE(src[8:12]))
		a1, a2, b1, b2 = magmaCrypt32x2T16(&c.encKeys, t16, a1, a2, b1, b2)
		store32BE(dst[0:4], uint32(a1))
		store32BE(dst[4:8], uint32(a2))
		store32BE(dst[8:12], uint32(b1))
		store32BE(dst[12:16], uint32(b2))
		dst = dst[2*BlockSize:]
		src = src[2*BlockSize:]
	}
	for len(src) >= BlockSize {
		n1, n2 := magmaCrypt32T16(&c.encKeys, t16, word(load32BE(src[4:8])), word(load32BE(src[0:4])))
		store32BE(dst[0:4], uint32(n1))
		store32BE(dst[4:8], uint32(n2))
		dst = dst[BlockSize:]
		src = src[BlockSize:]
	}
}

func (c *Cipher) XORKeyStreamCTR(dst, src, iv []byte) {
	if len(iv) != BlockSize && len(iv) != BlockSize/2 {
		panic("gogost/gost341264: Некорректный размер IV")
	}
	var counter [BlockSize]byte
	copy(counter[:], iv)
	c.XORKeyStreamCTRCounter(dst, src, counter[:])
}

func (c *Cipher) XORKeyStreamCTRCounter(dst, src, counter []byte) {
	if len(dst) < len(src) {
		panic("gogost/gost341264: dst слишком короткий")
	}
	if len(counter) != BlockSize {
		panic("gogost/gost341264: Некорректный размер счётчика")
	}
	keys := &c.encKeys
	t16 := c.t16
	left := load32BE(counter[0:4])
	right := load32BE(counter[4:8])
	if n, nextRight := xorKeyStreamCTRSIMD(c, dst, src, left, right); n > 0 {
		right = nextRight
		dst = dst[n:]
		src = src[n:]
	}
	for len(src) >= 4*BlockSize {
		g10, g20, g11, g21, g12, g22, g13, g23 := magmaCrypt32x4T16(
			keys, t16,
			word(right), word(left),
			word(right+1), word(left),
			word(right+2), word(left),
			word(right+3), word(left),
		)
		store32BE(dst[0:4], load32BE(src[0:4])^uint32(g10))
		store32BE(dst[4:8], load32BE(src[4:8])^uint32(g20))
		store32BE(dst[8:12], load32BE(src[8:12])^uint32(g11))
		store32BE(dst[12:16], load32BE(src[12:16])^uint32(g21))
		store32BE(dst[16:20], load32BE(src[16:20])^uint32(g12))
		store32BE(dst[20:24], load32BE(src[20:24])^uint32(g22))
		store32BE(dst[24:28], load32BE(src[24:28])^uint32(g13))
		store32BE(dst[28:32], load32BE(src[28:32])^uint32(g23))
		right += 4
		dst = dst[4*BlockSize:]
		src = src[4*BlockSize:]
	}
	for len(src) >= 2*BlockSize {
		g10, g20, g11, g21 := magmaCrypt32x2T16(
			keys, t16,
			word(right), word(left),
			word(right+1), word(left),
		)
		store32BE(dst[0:4], load32BE(src[0:4])^uint32(g10))
		store32BE(dst[4:8], load32BE(src[4:8])^uint32(g20))
		store32BE(dst[8:12], load32BE(src[8:12])^uint32(g11))
		store32BE(dst[12:16], load32BE(src[12:16])^uint32(g21))
		right += 2
		dst = dst[2*BlockSize:]
		src = src[2*BlockSize:]
	}
	for len(src) >= BlockSize {
		g1, g2 := magmaCrypt32T16(keys, t16, word(right), word(left))
		store32BE(dst[0:4], load32BE(src[0:4])^uint32(g1))
		store32BE(dst[4:8], load32BE(src[4:8])^uint32(g2))
		right++
		dst = dst[BlockSize:]
		src = src[BlockSize:]
	}
	if len(src) > 0 {
		g1, g2 := magmaCrypt32T16(keys, t16, word(right), word(left))
		var gamma [BlockSize]byte
		store32BE(gamma[0:4], uint32(g1))
		store32BE(gamma[4:8], uint32(g2))
		for i := range src {
			dst[i] = src[i] ^ gamma[i]
		}
		right++
	}
	store32BE(counter[4:8], right)
}

func (c *Cipher) encryptWords(n1, n2 word) (uint32, uint32) {
	n1, n2 = magmaCrypt32EncryptT16(&c.baseKeys, c.t16, n1, n2)
	return uint32(n1), uint32(n2)
}

func makeMagmaTable() [4][256]word {
	var table [4][256]word
	for pos := range 4 {
		lo := magmaSbox[pos*2]
		hi := magmaSbox[pos*2+1]
		shift := uint(pos * 8)
		for b := range 256 {
			v := word(lo[b&0x0f])<<shift | word(hi[b>>4])<<(shift+4)
			table[pos][b] = v<<11 | v>>(32-11)
		}
	}
	return table
}

func magmaSboxLookup(table *[4][256]word, n word) word {
	return table[0][byte(n)] ^
		table[1][byte(n>>8)] ^
		table[2][byte(n>>16)] ^
		table[3][byte(n>>24)]
}

// magmaCrypt32x4Encrypt — encrypt-only bulk core для четырёх независимых
// блоков. 32 раунда намеренно развёрнуты, чтобы убрать цикл по раундовым ключам
// из EncryptBlocks и сохранить single-block path компактным.
func magmaCrypt32x4Encrypt(
	keys *[8]word,
	table *[4][256]word,
	a1, a2, b1, b2, c1, c2, d1, d2 word,
) (word, word, word, word, word, word, word, word) {
	k0, k1, k2, k3 := keys[0], keys[1], keys[2], keys[3]
	k4, k5, k6, k7 := keys[4], keys[5], keys[6], keys[7]

	a1, a2 = magmaSboxLookup(table, a1+k0)^a2, a1
	b1, b2 = magmaSboxLookup(table, b1+k0)^b2, b1
	c1, c2 = magmaSboxLookup(table, c1+k0)^c2, c1
	d1, d2 = magmaSboxLookup(table, d1+k0)^d2, d1
	a1, a2 = magmaSboxLookup(table, a1+k1)^a2, a1
	b1, b2 = magmaSboxLookup(table, b1+k1)^b2, b1
	c1, c2 = magmaSboxLookup(table, c1+k1)^c2, c1
	d1, d2 = magmaSboxLookup(table, d1+k1)^d2, d1
	a1, a2 = magmaSboxLookup(table, a1+k2)^a2, a1
	b1, b2 = magmaSboxLookup(table, b1+k2)^b2, b1
	c1, c2 = magmaSboxLookup(table, c1+k2)^c2, c1
	d1, d2 = magmaSboxLookup(table, d1+k2)^d2, d1
	a1, a2 = magmaSboxLookup(table, a1+k3)^a2, a1
	b1, b2 = magmaSboxLookup(table, b1+k3)^b2, b1
	c1, c2 = magmaSboxLookup(table, c1+k3)^c2, c1
	d1, d2 = magmaSboxLookup(table, d1+k3)^d2, d1
	a1, a2 = magmaSboxLookup(table, a1+k4)^a2, a1
	b1, b2 = magmaSboxLookup(table, b1+k4)^b2, b1
	c1, c2 = magmaSboxLookup(table, c1+k4)^c2, c1
	d1, d2 = magmaSboxLookup(table, d1+k4)^d2, d1
	a1, a2 = magmaSboxLookup(table, a1+k5)^a2, a1
	b1, b2 = magmaSboxLookup(table, b1+k5)^b2, b1
	c1, c2 = magmaSboxLookup(table, c1+k5)^c2, c1
	d1, d2 = magmaSboxLookup(table, d1+k5)^d2, d1
	a1, a2 = magmaSboxLookup(table, a1+k6)^a2, a1
	b1, b2 = magmaSboxLookup(table, b1+k6)^b2, b1
	c1, c2 = magmaSboxLookup(table, c1+k6)^c2, c1
	d1, d2 = magmaSboxLookup(table, d1+k6)^d2, d1
	a1, a2 = magmaSboxLookup(table, a1+k7)^a2, a1
	b1, b2 = magmaSboxLookup(table, b1+k7)^b2, b1
	c1, c2 = magmaSboxLookup(table, c1+k7)^c2, c1
	d1, d2 = magmaSboxLookup(table, d1+k7)^d2, d1

	a1, a2 = magmaSboxLookup(table, a1+k0)^a2, a1
	b1, b2 = magmaSboxLookup(table, b1+k0)^b2, b1
	c1, c2 = magmaSboxLookup(table, c1+k0)^c2, c1
	d1, d2 = magmaSboxLookup(table, d1+k0)^d2, d1
	a1, a2 = magmaSboxLookup(table, a1+k1)^a2, a1
	b1, b2 = magmaSboxLookup(table, b1+k1)^b2, b1
	c1, c2 = magmaSboxLookup(table, c1+k1)^c2, c1
	d1, d2 = magmaSboxLookup(table, d1+k1)^d2, d1
	a1, a2 = magmaSboxLookup(table, a1+k2)^a2, a1
	b1, b2 = magmaSboxLookup(table, b1+k2)^b2, b1
	c1, c2 = magmaSboxLookup(table, c1+k2)^c2, c1
	d1, d2 = magmaSboxLookup(table, d1+k2)^d2, d1
	a1, a2 = magmaSboxLookup(table, a1+k3)^a2, a1
	b1, b2 = magmaSboxLookup(table, b1+k3)^b2, b1
	c1, c2 = magmaSboxLookup(table, c1+k3)^c2, c1
	d1, d2 = magmaSboxLookup(table, d1+k3)^d2, d1
	a1, a2 = magmaSboxLookup(table, a1+k4)^a2, a1
	b1, b2 = magmaSboxLookup(table, b1+k4)^b2, b1
	c1, c2 = magmaSboxLookup(table, c1+k4)^c2, c1
	d1, d2 = magmaSboxLookup(table, d1+k4)^d2, d1
	a1, a2 = magmaSboxLookup(table, a1+k5)^a2, a1
	b1, b2 = magmaSboxLookup(table, b1+k5)^b2, b1
	c1, c2 = magmaSboxLookup(table, c1+k5)^c2, c1
	d1, d2 = magmaSboxLookup(table, d1+k5)^d2, d1
	a1, a2 = magmaSboxLookup(table, a1+k6)^a2, a1
	b1, b2 = magmaSboxLookup(table, b1+k6)^b2, b1
	c1, c2 = magmaSboxLookup(table, c1+k6)^c2, c1
	d1, d2 = magmaSboxLookup(table, d1+k6)^d2, d1
	a1, a2 = magmaSboxLookup(table, a1+k7)^a2, a1
	b1, b2 = magmaSboxLookup(table, b1+k7)^b2, b1
	c1, c2 = magmaSboxLookup(table, c1+k7)^c2, c1
	d1, d2 = magmaSboxLookup(table, d1+k7)^d2, d1

	a1, a2 = magmaSboxLookup(table, a1+k0)^a2, a1
	b1, b2 = magmaSboxLookup(table, b1+k0)^b2, b1
	c1, c2 = magmaSboxLookup(table, c1+k0)^c2, c1
	d1, d2 = magmaSboxLookup(table, d1+k0)^d2, d1
	a1, a2 = magmaSboxLookup(table, a1+k1)^a2, a1
	b1, b2 = magmaSboxLookup(table, b1+k1)^b2, b1
	c1, c2 = magmaSboxLookup(table, c1+k1)^c2, c1
	d1, d2 = magmaSboxLookup(table, d1+k1)^d2, d1
	a1, a2 = magmaSboxLookup(table, a1+k2)^a2, a1
	b1, b2 = magmaSboxLookup(table, b1+k2)^b2, b1
	c1, c2 = magmaSboxLookup(table, c1+k2)^c2, c1
	d1, d2 = magmaSboxLookup(table, d1+k2)^d2, d1
	a1, a2 = magmaSboxLookup(table, a1+k3)^a2, a1
	b1, b2 = magmaSboxLookup(table, b1+k3)^b2, b1
	c1, c2 = magmaSboxLookup(table, c1+k3)^c2, c1
	d1, d2 = magmaSboxLookup(table, d1+k3)^d2, d1
	a1, a2 = magmaSboxLookup(table, a1+k4)^a2, a1
	b1, b2 = magmaSboxLookup(table, b1+k4)^b2, b1
	c1, c2 = magmaSboxLookup(table, c1+k4)^c2, c1
	d1, d2 = magmaSboxLookup(table, d1+k4)^d2, d1
	a1, a2 = magmaSboxLookup(table, a1+k5)^a2, a1
	b1, b2 = magmaSboxLookup(table, b1+k5)^b2, b1
	c1, c2 = magmaSboxLookup(table, c1+k5)^c2, c1
	d1, d2 = magmaSboxLookup(table, d1+k5)^d2, d1
	a1, a2 = magmaSboxLookup(table, a1+k6)^a2, a1
	b1, b2 = magmaSboxLookup(table, b1+k6)^b2, b1
	c1, c2 = magmaSboxLookup(table, c1+k6)^c2, c1
	d1, d2 = magmaSboxLookup(table, d1+k6)^d2, d1
	a1, a2 = magmaSboxLookup(table, a1+k7)^a2, a1
	b1, b2 = magmaSboxLookup(table, b1+k7)^b2, b1
	c1, c2 = magmaSboxLookup(table, c1+k7)^c2, c1
	d1, d2 = magmaSboxLookup(table, d1+k7)^d2, d1

	a1, a2 = magmaSboxLookup(table, a1+k7)^a2, a1
	b1, b2 = magmaSboxLookup(table, b1+k7)^b2, b1
	c1, c2 = magmaSboxLookup(table, c1+k7)^c2, c1
	d1, d2 = magmaSboxLookup(table, d1+k7)^d2, d1
	a1, a2 = magmaSboxLookup(table, a1+k6)^a2, a1
	b1, b2 = magmaSboxLookup(table, b1+k6)^b2, b1
	c1, c2 = magmaSboxLookup(table, c1+k6)^c2, c1
	d1, d2 = magmaSboxLookup(table, d1+k6)^d2, d1
	a1, a2 = magmaSboxLookup(table, a1+k5)^a2, a1
	b1, b2 = magmaSboxLookup(table, b1+k5)^b2, b1
	c1, c2 = magmaSboxLookup(table, c1+k5)^c2, c1
	d1, d2 = magmaSboxLookup(table, d1+k5)^d2, d1
	a1, a2 = magmaSboxLookup(table, a1+k4)^a2, a1
	b1, b2 = magmaSboxLookup(table, b1+k4)^b2, b1
	c1, c2 = magmaSboxLookup(table, c1+k4)^c2, c1
	d1, d2 = magmaSboxLookup(table, d1+k4)^d2, d1
	a1, a2 = magmaSboxLookup(table, a1+k3)^a2, a1
	b1, b2 = magmaSboxLookup(table, b1+k3)^b2, b1
	c1, c2 = magmaSboxLookup(table, c1+k3)^c2, c1
	d1, d2 = magmaSboxLookup(table, d1+k3)^d2, d1
	a1, a2 = magmaSboxLookup(table, a1+k2)^a2, a1
	b1, b2 = magmaSboxLookup(table, b1+k2)^b2, b1
	c1, c2 = magmaSboxLookup(table, c1+k2)^c2, c1
	d1, d2 = magmaSboxLookup(table, d1+k2)^d2, d1
	a1, a2 = magmaSboxLookup(table, a1+k1)^a2, a1
	b1, b2 = magmaSboxLookup(table, b1+k1)^b2, b1
	c1, c2 = magmaSboxLookup(table, c1+k1)^c2, c1
	d1, d2 = magmaSboxLookup(table, d1+k1)^d2, d1
	a1, a2 = magmaSboxLookup(table, a1+k0)^a2, a1
	b1, b2 = magmaSboxLookup(table, b1+k0)^b2, b1
	c1, c2 = magmaSboxLookup(table, c1+k0)^c2, c1
	d1, d2 = magmaSboxLookup(table, d1+k0)^d2, d1
	return a1, a2, b1, b2, c1, c2, d1, d2
}

func magmaCrypt32(keys *[32]word, table *[4][256]word, n1, n2 word) (word, word) {
	n1, n2 = magmaSboxLookup(table, n1+keys[0])^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+keys[1])^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+keys[2])^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+keys[3])^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+keys[4])^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+keys[5])^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+keys[6])^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+keys[7])^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+keys[8])^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+keys[9])^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+keys[10])^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+keys[11])^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+keys[12])^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+keys[13])^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+keys[14])^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+keys[15])^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+keys[16])^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+keys[17])^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+keys[18])^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+keys[19])^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+keys[20])^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+keys[21])^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+keys[22])^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+keys[23])^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+keys[24])^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+keys[25])^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+keys[26])^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+keys[27])^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+keys[28])^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+keys[29])^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+keys[30])^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+keys[31])^n2, n1
	return n1, n2
}

func magmaCrypt32Encrypt(keys *[8]word, table *[4][256]word, n1, n2 word) (word, word) {
	k0, k1, k2, k3 := keys[0], keys[1], keys[2], keys[3]
	k4, k5, k6, k7 := keys[4], keys[5], keys[6], keys[7]

	n1, n2 = magmaSboxLookup(table, n1+k0)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k1)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k2)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k3)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k4)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k5)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k6)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k7)^n2, n1

	n1, n2 = magmaSboxLookup(table, n1+k0)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k1)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k2)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k3)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k4)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k5)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k6)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k7)^n2, n1

	n1, n2 = magmaSboxLookup(table, n1+k0)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k1)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k2)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k3)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k4)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k5)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k6)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k7)^n2, n1

	n1, n2 = magmaSboxLookup(table, n1+k7)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k6)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k5)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k4)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k3)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k2)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k1)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k0)^n2, n1
	return n1, n2
}

func magmaCrypt32Decrypt(keys *[8]word, table *[4][256]word, n1, n2 word) (word, word) {
	k0, k1, k2, k3 := keys[0], keys[1], keys[2], keys[3]
	k4, k5, k6, k7 := keys[4], keys[5], keys[6], keys[7]

	n1, n2 = magmaSboxLookup(table, n1+k0)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k1)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k2)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k3)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k4)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k5)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k6)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k7)^n2, n1

	n1, n2 = magmaSboxLookup(table, n1+k7)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k6)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k5)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k4)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k3)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k2)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k1)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k0)^n2, n1

	n1, n2 = magmaSboxLookup(table, n1+k7)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k6)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k5)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k4)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k3)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k2)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k1)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k0)^n2, n1

	n1, n2 = magmaSboxLookup(table, n1+k7)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k6)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k5)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k4)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k3)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k2)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k1)^n2, n1
	n1, n2 = magmaSboxLookup(table, n1+k0)^n2, n1
	return n1, n2
}

func magmaCrypt32x2(
	keys *[32]word,
	table *[4][256]word,
	a1, a2, b1, b2 word,
) (word, word, word, word) {
	for i := 0; i < 32; i++ {
		k := keys[i]
		a1, a2 = magmaSboxLookup(table, a1+k)^a2, a1
		b1, b2 = magmaSboxLookup(table, b1+k)^b2, b1
	}
	return a1, a2, b1, b2
}

func magmaCrypt32x4(
	keys *[32]word,
	table *[4][256]word,
	a1, a2, b1, b2, c1, c2, d1, d2 word,
) (word, word, word, word, word, word, word, word) {
	for i := 0; i < 32; i++ {
		k := keys[i]
		a1, a2 = magmaSboxLookup(table, a1+k)^a2, a1
		b1, b2 = magmaSboxLookup(table, b1+k)^b2, b1
		c1, c2 = magmaSboxLookup(table, c1+k)^c2, c1
		d1, d2 = magmaSboxLookup(table, d1+k)^d2, d1
	}
	return a1, a2, b1, b2, c1, c2, d1, d2
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
