package gost28147

type CFBEncrypter struct {
	c       *Cipher
	iv      [BlockSize]byte
	gamma   [BlockSize]byte
	gammaOf int // сколько байт гаммы уже использовано (0..BlockSize)
}

func (c *Cipher) NewCFBEncrypter(iv []byte) *CFBEncrypter {
	if len(iv) != BlockSize {
		panic("gogost/gost28147: длина IV не равна размеру блока")
	}
	e := &CFBEncrypter{c: c, gammaOf: BlockSize} // принудим генерацию гаммы на первом вызове
	copy(e.iv[:], iv)
	return e
}

func (e *CFBEncrypter) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("gogost/gost28147: dst слишком короткий")
	}

	for len(src) > 0 {
		if e.gammaOf == BlockSize && len(src) >= BlockSize {
			ciphertext := load64LE(src[:BlockSize]) ^ e.c.encryptBlock64CFB(load64LE(e.iv[:]))
			store64LE(dst[:BlockSize], ciphertext)
			store64LE(e.iv[:], ciphertext)
			dst, src = dst[BlockSize:], src[BlockSize:]
			continue
		}
		// Если гамма кончилась — генерируем новую из текущего IV (feedback = ciphertext)
		if e.gammaOf == BlockSize {
			store64LE(e.gamma[:], e.c.encryptBlock64CFB(load64LE(e.iv[:])))
			e.gammaOf = 0
		}

		n := BlockSize - e.gammaOf
		if len(src) < n {
			n = len(src)
		}

		off := e.gammaOf

		// XOR + обновление feedback (IV) ciphertext-ом
		for i := range n {
			cbyte := src[i] ^ e.gamma[off+i]
			dst[i] = cbyte
			e.iv[off+i] = cbyte
		}

		e.gammaOf += n
		dst = dst[n:]
		src = src[n:]
	}
}

type CFBDecrypter struct {
	c       *Cipher
	iv      [BlockSize]byte
	gamma   [BlockSize]byte
	gammaOf int
}

func (c *Cipher) NewCFBDecrypter(iv []byte) *CFBDecrypter {
	if len(iv) != BlockSize {
		panic("gogost/gost28147: длина IV не равна размеру блока")
	}
	d := &CFBDecrypter{c: c, gammaOf: BlockSize}
	copy(d.iv[:], iv)
	return d
}

func (d *CFBDecrypter) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("gogost/gost28147: dst слишком короткий")
	}

	for len(src) > 0 {
		if d.gammaOf == BlockSize && len(src) >= BlockSize {
			ciphertext := load64LE(src[:BlockSize])
			plaintext := ciphertext ^ d.c.encryptBlock64CFB(load64LE(d.iv[:]))
			store64LE(dst[:BlockSize], plaintext)
			store64LE(d.iv[:], ciphertext)
			dst, src = dst[BlockSize:], src[BlockSize:]
			continue
		}
		if d.gammaOf == BlockSize {
			store64LE(d.gamma[:], d.c.encryptBlock64CFB(load64LE(d.iv[:])))
			d.gammaOf = 0
		}

		n := BlockSize - d.gammaOf
		if len(src) < n {
			n = len(src)
		}

		off := d.gammaOf

		// plaintext = ciphertext XOR gamma
		// feedback (IV) обновляется ciphertext-ом (src)
		for i := range n {
			ciphertext := src[i]
			dst[i] = ciphertext ^ d.gamma[off+i]
			d.iv[off+i] = ciphertext
		}

		d.gammaOf += n
		dst = dst[n:]
		src = src[n:]
	}
}
