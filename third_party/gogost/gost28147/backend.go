//go:build purego || !amd64

package gost28147

func encryptBlocksSIMD(dst, src []byte, keys *[32]nv, sbox *[8][32]byte) int {
	return 0
}

func decryptBlocksSIMD(dst, src []byte, keys *[32]nv, sbox *[8][32]byte) int {
	return 0
}

func xorKeyStreamCTRSIMD(ctr *CTR, dst, src []byte) int {
	return 0
}

func xorKeyStreamGOST3413CTRSIMD(c *Cipher, dst, src, counter []byte) int {
	return 0
}
