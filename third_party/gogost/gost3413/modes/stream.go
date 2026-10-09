package modes

// CFB представляет подготовленный режим обратной связи по шифртексту.
type CFB struct {
	block        blockCipher
	bulk         blockBulkCipher
	fast         feedbackCipher
	parallel     parallelState
	blockSize    int
	iv           [32]byte
	ivHeap       []byte
	segmentSize  int
	registerSize int
	register     [32]byte
	registerHeap []byte
	gamma        [16]byte
}

// OFB представляет подготовленный режим обратной связи по выходу.
type OFB struct {
	block        blockCipher
	fast         feedbackCipher
	blockSize    int
	iv           [32]byte
	ivHeap       []byte
	segmentSize  int
	registerSize int
	register     [32]byte
	registerHeap []byte
	gamma        [16]byte
}

// CTR представляет подготовленный счётчиковый режим.
type CTR struct {
	block       blockCipher
	fast        ctrCounterBlock
	parallel    parallelState
	blockSize   int
	segmentSize int
	iv          [16]byte
	counter     [16]byte
	gamma       [16]byte
}

type feedbackCipher interface {
	EncryptCFB(dst, src, iv []byte)
	DecryptCFB(dst, src, iv []byte)
	XORKeyStreamOFB(dst, src, iv []byte)
}

func (c *CFB) Encrypt(dst, plaintext []byte) ([]byte, error) {
	dstLen := len(dst)
	ret, out, err := sliceForAppendChecked(dst, plaintext, len(plaintext))
	if err != nil {
		return nil, err
	}
	written, err := c.cryptInto(out, plaintext, true, 0)
	if err != nil {
		return nil, err
	}
	return ret[:dstLen+len(written)], nil
}

// EncryptWithWorkers проверяет workers и шифрует последовательно, потому что
// CFB-шифрование зависит от предыдущего сегмента ciphertext.
func (c *CFB) EncryptWithWorkers(dst, plaintext []byte, workers int) ([]byte, error) {
	if _, err := manualWorkers(len(plaintext), c.blockSize, workers); err != nil {
		return nil, err
	}
	return c.Encrypt(dst, plaintext)
}

// SetWorkers настраивает постоянный worker pool для full-block CFB-расшифрования.
// CFB-шифрование остаётся последовательным, потому что feedback зависит от
// предыдущего сегмента ciphertext.
func (c *CFB) SetWorkers(workers int) error {
	return c.parallel.setWorkers(workers)
}

// ResetWorkers возвращает CFB-расшифрование к автоматическому выбору workers.
func (c *CFB) ResetWorkers() {
	c.parallel.resetWorkers()
}

// Close освобождает worker-ресурсы CFB. Объект можно использовать снова.
func (c *CFB) Close() {
	c.parallel.close()
}

func (c *CFB) Decrypt(dst, ciphertext []byte) ([]byte, error) {
	dstLen := len(dst)
	ret, out, err := sliceForAppendChecked(dst, ciphertext, len(ciphertext))
	if err != nil {
		return nil, err
	}
	written, err := c.cryptInto(out, ciphertext, false, 0)
	if err != nil {
		return nil, err
	}
	return ret[:dstLen+len(written)], nil
}

// DecryptWithWorkers работает как Decrypt, но использует заданное число workers
// для full-block CFB-расшифрования, если буферы допускают параллельную обработку.
func (c *CFB) DecryptWithWorkers(dst, ciphertext []byte, workers int) ([]byte, error) {
	dstLen := len(dst)
	workers, err := manualWorkers(len(ciphertext), c.blockSize, workers)
	if err != nil {
		return nil, err
	}
	ret, out, err := sliceForAppendChecked(dst, ciphertext, len(ciphertext))
	if err != nil {
		return nil, err
	}
	written, err := c.cryptInto(out, ciphertext, false, workers)
	if err != nil {
		return nil, err
	}
	return ret[:dstLen+len(written)], nil
}

// EncryptTo шифрует plaintext в dst без append-роста результата.
func (c *CFB) EncryptTo(dst, plaintext []byte) ([]byte, error) {
	return c.cryptTo(dst, plaintext, true, 0)
}

// EncryptToWithWorkers проверяет workers и шифрует последовательно, потому что
// CFB-шифрование зависит от предыдущего сегмента ciphertext.
func (c *CFB) EncryptToWithWorkers(dst, plaintext []byte, workers int) ([]byte, error) {
	if _, err := manualWorkers(len(plaintext), c.blockSize, workers); err != nil {
		return nil, err
	}
	return c.EncryptTo(dst, plaintext)
}

// DecryptTo расшифровывает ciphertext в dst без append-роста результата.
func (c *CFB) DecryptTo(dst, ciphertext []byte) ([]byte, error) {
	return c.cryptTo(dst, ciphertext, false, 0)
}

// DecryptToWithWorkers расшифровывает ciphertext в dst с заданным числом workers.
// workers должно быть больше 1.
func (c *CFB) DecryptToWithWorkers(dst, ciphertext []byte, workers int) ([]byte, error) {
	workers, err := manualWorkers(len(ciphertext), c.blockSize, workers)
	if err != nil {
		return nil, err
	}
	return c.cryptTo(dst, ciphertext, false, workers)
}

func (c *CFB) cryptTo(dst, src []byte, encrypt bool, workers int) ([]byte, error) {
	out, err := sliceForWriteChecked(dst, src, len(src))
	if err != nil {
		return nil, err
	}
	return c.cryptInto(out, src, encrypt, workers)
}

func (c *CFB) cryptInto(out, src []byte, encrypt bool, workers int) ([]byte, error) {
	written := len(src)
	out = out[:written]
	ret := out
	if len(src) == 0 {
		return out, nil
	}
	if len(src) <= c.blockSize && c.segmentSize == c.blockSize && c.registerSize == c.blockSize {
		c.block.Encrypt(c.gamma[:c.blockSize], c.iv[:c.blockSize])
		xorOneBlockOrPartial(out, src, c.gamma[:c.blockSize], len(src))
		return out, nil
	}
	if !encrypt && c.bulk != nil && len(src) >= 8*c.blockSize && !sameStart(out, src) &&
		c.segmentSize == c.blockSize && c.registerSize == c.blockSize {
		workers = c.parallel.workers(len(src), c.blockSize, workers, parallelBlockMinBytes)
		c.decryptBulk(out, src, workers)
		return out, nil
	}
	if c.fast != nil {
		if encrypt {
			c.fast.EncryptCFB(out, src, c.iv[:c.blockSize])
		} else {
			c.fast.DecryptCFB(out, src, c.iv[:c.blockSize])
		}
		return out, nil
	}
	register := c.registerBytes()
	copy(register, c.ivBytes())

	var feedback [16]byte
	for len(src) > 0 {
		c.block.Encrypt(c.gamma[:c.blockSize], register[:c.blockSize])
		n := min(c.segmentSize, len(src))
		if !encrypt {
			copy(feedback[:], src[:n])
		}
		for i := 0; i < n; i++ {
			out[i] = src[i] ^ c.gamma[i]
		}
		if encrypt {
			shiftRegister(register, out[:n])
		} else {
			shiftRegister(register, feedback[:n])
		}
		out = out[n:]
		src = src[n:]
	}
	return ret[:written], nil
}

func (c *CFB) decryptBulk(out, src []byte, workers int) {
	fullLen := len(src) - len(src)%c.blockSize
	gamma := c.gamma[:c.blockSize]

	if workers > 1 && fullLen >= 2*c.blockSize {
		c.decryptBulkParallel(out, src, fullLen, workers)
		return
	}
	c.block.Encrypt(gamma, c.iv[:c.blockSize])
	if fullLen == 0 {
		xorPartial(out, src, gamma)
		return
	}

	xorIntoBlock(out[:c.blockSize], src[:c.blockSize], gamma, c.blockSize)
	if fullLen > c.blockSize {
		c.bulk.EncryptBlocks(out[c.blockSize:fullLen], src[:fullLen-c.blockSize])
		xorBlocksInPlace(out[c.blockSize:fullLen], src[c.blockSize:fullLen], c.blockSize)
	}
	if fullLen < len(src) {
		c.block.Encrypt(gamma, src[fullLen-c.blockSize:fullLen])
		xorPartial(out[fullLen:len(src)], src[fullLen:], gamma)
	}
}

func (c *CFB) decryptBulkParallel(out, src []byte, fullLen, workers int) {
	c.parallel.runOp(fullLen, c.blockSize, workers, parallelOpCFBDecrypt, parallelContext{
		block:     c.block,
		bulk:      c.bulk,
		dst:       out,
		src:       src,
		iv:        c.iv[:c.blockSize],
		blockSize: c.blockSize,
	})
	if fullLen < len(src) {
		var gamma [16]byte
		c.block.Encrypt(gamma[:c.blockSize], src[fullLen-c.blockSize:fullLen])
		xorPartial(out[fullLen:len(src)], src[fullLen:], gamma[:c.blockSize])
	}
}

func (o *OFB) Encrypt(dst, plaintext []byte) ([]byte, error) {
	return o.XORKeyStream(dst, plaintext)
}

func (o *OFB) Decrypt(dst, ciphertext []byte) ([]byte, error) {
	return o.XORKeyStream(dst, ciphertext)
}

func (o *OFB) EncryptTo(dst, plaintext []byte) ([]byte, error) {
	return o.XORKeyStreamTo(dst, plaintext)
}

func (o *OFB) DecryptTo(dst, ciphertext []byte) ([]byte, error) {
	return o.XORKeyStreamTo(dst, ciphertext)
}

// EncryptWithWorkers проверяет workers и шифрует последовательно, потому что
// генерация гаммы OFB зависит от feedback.
func (o *OFB) EncryptWithWorkers(dst, plaintext []byte, workers int) ([]byte, error) {
	return o.XORKeyStreamWithWorkers(dst, plaintext, workers)
}

// DecryptWithWorkers проверяет workers и расшифровывает последовательно, потому
// что генерация гаммы OFB зависит от feedback.
func (o *OFB) DecryptWithWorkers(dst, ciphertext []byte, workers int) ([]byte, error) {
	return o.XORKeyStreamWithWorkers(dst, ciphertext, workers)
}

// EncryptToWithWorkers проверяет workers и шифрует последовательно, потому что
// генерация гаммы OFB зависит от feedback.
func (o *OFB) EncryptToWithWorkers(dst, plaintext []byte, workers int) ([]byte, error) {
	return o.XORKeyStreamToWithWorkers(dst, plaintext, workers)
}

// DecryptToWithWorkers проверяет workers и расшифровывает последовательно, потому
// что генерация гаммы OFB зависит от feedback.
func (o *OFB) DecryptToWithWorkers(dst, ciphertext []byte, workers int) ([]byte, error) {
	return o.XORKeyStreamToWithWorkers(dst, ciphertext, workers)
}

func (o *OFB) XORKeyStream(dst, src []byte) ([]byte, error) {
	dstLen := len(dst)
	ret, out, err := sliceForAppendChecked(dst, src, len(src))
	if err != nil {
		return nil, err
	}
	written, err := o.xorKeyStreamInto(out, src)
	if err != nil {
		return nil, err
	}
	return ret[:dstLen+len(written)], nil
}

// XORKeyStreamWithWorkers проверяет workers и выполняет последовательный OFB stream.
func (o *OFB) XORKeyStreamWithWorkers(dst, src []byte, workers int) ([]byte, error) {
	if _, err := manualWorkers(len(src), o.blockSize, workers); err != nil {
		return nil, err
	}
	return o.XORKeyStream(dst, src)
}

// XORKeyStreamTo применяет XOR src к dst без append-роста результата.
func (o *OFB) XORKeyStreamTo(dst, src []byte) ([]byte, error) {
	out, err := sliceForWriteChecked(dst, src, len(src))
	if err != nil {
		return nil, err
	}
	return o.xorKeyStreamInto(out, src)
}

func (o *OFB) xorKeyStreamInto(out, src []byte) ([]byte, error) {
	written := len(src)
	out = out[:written]
	ret := out
	if len(src) == 0 {
		return out, nil
	}
	if len(src) <= o.blockSize && o.segmentSize == o.blockSize && o.registerSize == o.blockSize {
		o.block.Encrypt(o.gamma[:o.blockSize], o.iv[:o.blockSize])
		xorOneBlockOrPartial(out, src, o.gamma[:o.blockSize], len(src))
		return out, nil
	}
	if o.fast != nil {
		o.fast.XORKeyStreamOFB(out, src, o.iv[:o.blockSize])
		return out, nil
	}
	register := o.registerBytes()
	copy(register, o.ivBytes())

	for len(src) > 0 {
		o.block.Encrypt(o.gamma[:o.blockSize], register[:o.blockSize])
		n := min(o.segmentSize, len(src))
		for i := 0; i < n; i++ {
			out[i] = src[i] ^ o.gamma[i]
		}
		shiftRegister(register, o.gamma[:n])
		out = out[n:]
		src = src[n:]
	}
	return ret[:written], nil
}

// XORKeyStreamToWithWorkers проверяет workers и выполняет последовательный OFB stream.
func (o *OFB) XORKeyStreamToWithWorkers(dst, src []byte, workers int) ([]byte, error) {
	if _, err := manualWorkers(len(src), o.blockSize, workers); err != nil {
		return nil, err
	}
	return o.XORKeyStreamTo(dst, src)
}

func (c *CTR) Encrypt(dst, plaintext []byte) ([]byte, error) {
	return c.XORKeyStream(dst, plaintext)
}

func (c *CTR) Decrypt(dst, ciphertext []byte) ([]byte, error) {
	return c.XORKeyStream(dst, ciphertext)
}

func (c *CTR) EncryptTo(dst, plaintext []byte) ([]byte, error) {
	return c.XORKeyStreamTo(dst, plaintext)
}

func (c *CTR) DecryptTo(dst, ciphertext []byte) ([]byte, error) {
	return c.XORKeyStreamTo(dst, ciphertext)
}

func (c *CTR) EncryptWithWorkers(dst, plaintext []byte, workers int) ([]byte, error) {
	return c.XORKeyStreamWithWorkers(dst, plaintext, workers)
}

// SetWorkers настраивает постоянный worker pool для CTR stream.
func (c *CTR) SetWorkers(workers int) error {
	return c.parallel.setWorkers(workers)
}

// ResetWorkers возвращает CTR к автоматическому выбору workers.
func (c *CTR) ResetWorkers() {
	c.parallel.resetWorkers()
}

// Close освобождает worker-ресурсы CTR. Объект можно использовать снова.
func (c *CTR) Close() {
	c.parallel.close()
}

func (c *CTR) DecryptWithWorkers(dst, ciphertext []byte, workers int) ([]byte, error) {
	return c.XORKeyStreamWithWorkers(dst, ciphertext, workers)
}

func (c *CTR) EncryptToWithWorkers(dst, plaintext []byte, workers int) ([]byte, error) {
	return c.XORKeyStreamToWithWorkers(dst, plaintext, workers)
}

func (c *CTR) DecryptToWithWorkers(dst, ciphertext []byte, workers int) ([]byte, error) {
	return c.XORKeyStreamToWithWorkers(dst, ciphertext, workers)
}

func (c *CTR) XORKeyStream(dst, src []byte) ([]byte, error) {
	dstLen := len(dst)
	ret, out, err := sliceForAppendChecked(dst, src, len(src))
	if err != nil {
		return nil, err
	}
	written, err := c.xorKeyStreamInto(out, src, 0)
	if err != nil {
		return nil, err
	}
	return ret[:dstLen+len(written)], nil
}

// XORKeyStreamWithWorkers работает как XORKeyStream, но использует заданное
// число workers для независимых диапазонов счётчика. workers должно быть больше 1.
func (c *CTR) XORKeyStreamWithWorkers(dst, src []byte, workers int) ([]byte, error) {
	dstLen := len(dst)
	workers, err := manualWorkers(len(src), c.blockSize, workers)
	if err != nil {
		return nil, err
	}
	ret, out, err := sliceForAppendChecked(dst, src, len(src))
	if err != nil {
		return nil, err
	}
	written, err := c.xorKeyStreamInto(out, src, workers)
	if err != nil {
		return nil, err
	}
	return ret[:dstLen+len(written)], nil
}

// XORKeyStreamTo применяет XOR src к dst без append-роста результата.
func (c *CTR) XORKeyStreamTo(dst, src []byte) ([]byte, error) {
	return c.xorKeyStreamTo(dst, src, 0)
}

// XORKeyStreamToWithWorkers применяет XOR src к dst с заданным числом workers.
// workers должно быть больше 1.
func (c *CTR) XORKeyStreamToWithWorkers(dst, src []byte, workers int) ([]byte, error) {
	workers, err := manualWorkers(len(src), c.blockSize, workers)
	if err != nil {
		return nil, err
	}
	return c.xorKeyStreamTo(dst, src, workers)
}

func (c *CTR) xorKeyStreamTo(dst, src []byte, workers int) ([]byte, error) {
	out, err := sliceForWriteChecked(dst, src, len(src))
	if err != nil {
		return nil, err
	}
	return c.xorKeyStreamInto(out, src, workers)
}

func (c *CTR) xorKeyStreamInto(out, src []byte, workers int) ([]byte, error) {
	out = out[:len(src)]
	if len(src) == 0 {
		return out, nil
	}
	if c.segmentSize != 0 && c.segmentSize != c.blockSize {
		normalizeCTRIVInto(c.counter[:c.blockSize], c.iv[:c.blockSize])
		for offset := 0; offset < len(src); offset += c.segmentSize {
			c.block.Encrypt(c.gamma[:c.blockSize], c.counter[:c.blockSize])
			n := min(c.segmentSize, len(src)-offset)
			for i := 0; i < n; i++ {
				out[offset+i] = src[offset+i] ^ c.gamma[i]
			}
			incCounter(c.counter[:c.blockSize])
		}
		return out, nil
	}
	if len(src) <= c.blockSize {
		normalizeCTRIVInto(c.counter[:c.blockSize], c.iv[:c.blockSize])
		c.block.Encrypt(c.gamma[:c.blockSize], c.counter[:c.blockSize])
		xorOneBlockOrPartial(out, src, c.gamma[:c.blockSize], len(src))
		return out, nil
	}
	workers = c.parallel.workers(len(src), c.blockSize, workers, parallelStreamMinBytes)
	if workers > 1 {
		c.xorKeyStreamParallel(out, src, workers)
		return out, nil
	}
	normalizeCTRIVInto(c.counter[:c.blockSize], c.iv[:c.blockSize])
	xorCTR(out, src, c.block, c.fast, c.counter[:c.blockSize], c.gamma[:c.blockSize])
	return out, nil
}

func (c *CTR) xorKeyStreamParallel(out, src []byte, workers int) {
	fullLen := len(src) - len(src)%c.blockSize
	if fullLen == 0 {
		normalizeCTRIVInto(c.counter[:c.blockSize], c.iv[:c.blockSize])
		xorCTR(out, src, c.block, c.fast, c.counter[:c.blockSize], c.gamma[:c.blockSize])
		return
	}
	c.parallel.runOp(fullLen, c.blockSize, workers, parallelOpCTR, parallelContext{
		block:     c.block,
		fast:      c.fast,
		dst:       out,
		src:       src,
		iv:        c.iv[:c.blockSize],
		blockSize: c.blockSize,
	})
	if fullLen < len(src) {
		var counter [16]byte
		counterForOffset(counter[:c.blockSize], c.iv[:c.blockSize], c.blockSize, fullLen/c.blockSize)
		xorCTR(out[fullLen:], src[fullLen:], c.block, c.fast, counter[:c.blockSize], c.gamma[:c.blockSize])
	}
}

func (c *CFB) registerBytes() []byte {
	if c.registerHeap != nil {
		return c.registerHeap[:c.registerSize]
	}
	return c.register[:c.registerSize]
}

func (c *CFB) ivBytes() []byte {
	if c.ivHeap != nil {
		return c.ivHeap[:c.registerSize]
	}
	return c.iv[:c.registerSize]
}

func (o *OFB) registerBytes() []byte {
	if o.registerHeap != nil {
		return o.registerHeap[:o.registerSize]
	}
	return o.register[:o.registerSize]
}

func (o *OFB) ivBytes() []byte {
	if o.ivHeap != nil {
		return o.ivHeap[:o.registerSize]
	}
	return o.iv[:o.registerSize]
}

func shiftRegister(register, feedback []byte) {
	copy(register, register[len(feedback):])
	copy(register[len(register)-len(feedback):], feedback)
}
