//go:build purego || !amd64

package gost341264

func (c *Cipher) encryptBlock64(v uint64) uint64 {
	n1, n2 := magmaCrypt32EncryptT16(&c.baseKeys, c.t16, word(uint32(v)), word(uint32(v>>32)))
	return uint64(uint32(n1))<<32 | uint64(uint32(n2))
}

func (c *Cipher) decryptBlock64(v uint64) uint64 {
	n1, n2 := magmaCrypt32DecryptT16(&c.baseKeys, c.t16, word(uint32(v)), word(uint32(v>>32)))
	return uint64(uint32(n1))<<32 | uint64(uint32(n2))
}

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

func encryptBlocksSIMD(dst, src []byte, keys *[32]word) int {
	return 0
}

func decryptBlocksSIMD(dst, src []byte, keys *[32]word) int {
	return 0
}

func xorKeyStreamCTRSIMD(c *Cipher, dst, src []byte, left, right uint32) (int, uint32) {
	return 0, right
}
