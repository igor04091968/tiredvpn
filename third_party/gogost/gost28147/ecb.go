package gost28147

type ECBEncrypter struct {
	c *Cipher
}

func (c *Cipher) NewECBEncrypter() *ECBEncrypter {
	e := ECBEncrypter{c}
	return &e
}

func (e *ECBEncrypter) CryptBlocks(dst, src []byte) {
	if len(src) >= 4*BlockSize {
		e.c.EncryptBlocks(dst, src)
		return
	}
	for i := 0; i < len(src); i += BlockSize {
		e.c.Encrypt(dst[i:i+BlockSize], src[i:i+BlockSize])
	}
}

func (e *ECBEncrypter) BlockSize() int {
	return e.c.BlockSize()
}

type ECBDecrypter struct {
	c *Cipher
}

func (c *Cipher) NewECBDecrypter() *ECBDecrypter {
	d := ECBDecrypter{c}
	return &d
}

func (e *ECBDecrypter) CryptBlocks(dst, src []byte) {
	if len(src) >= 4*BlockSize {
		e.c.DecryptBlocks(dst, src)
		return
	}
	for i := 0; i < len(src); i += BlockSize {
		e.c.Decrypt(dst[i:i+BlockSize], src[i:i+BlockSize])
	}
}

func (e *ECBDecrypter) BlockSize() int {
	return e.c.BlockSize()
}
