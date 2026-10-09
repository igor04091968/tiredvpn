package modes

import "unsafe"

// ECB представляет подготовленный режим простой замены.
type ECB struct {
	block     blockCipher
	bulk      blockBulkCipher
	parallel  parallelState
	blockSize int
	padding   Padding
	err       error
}

// CBC представляет подготовленный режим сцепления блоков.
type CBC struct {
	block     blockCipher
	bulk      blockBulkCipher
	fast      cbcCipher
	parallel  parallelState
	blockSize int
	iv        [16]byte
	ivHeap    []byte
	register  []byte
	padding   Padding
}

type blockCipher interface {
	BlockSize() int
	Encrypt(dst, src []byte)
	Decrypt(dst, src []byte)
}

type blockBulkCipher interface {
	EncryptBlocks(dst, src []byte)
	DecryptBlocks(dst, src []byte)
}

type cbcCipher interface {
	EncryptCBC(dst, src, iv []byte)
	DecryptCBC(dst, src, iv []byte)
}

func (e *ECB) Encrypt(dst, plaintext []byte) ([]byte, error) {
	if e.err != nil {
		return nil, e.err
	}
	dstLen := len(dst)
	n, err := encryptedSize(len(plaintext), e.blockSize, e.padding)
	if err != nil {
		return nil, err
	}
	ret, out, err := sliceForAppendChecked(dst, plaintext, n)
	if err != nil {
		return nil, err
	}
	written, err := e.encryptInto(out, plaintext, 0)
	if err != nil {
		return nil, err
	}
	return ret[:dstLen+len(written)], nil
}

// EncryptWithWorkers работает как Encrypt, но использует заданное число workers
// для режимов, где блоки можно обрабатывать независимо. workers должно быть больше 1.
func (e *ECB) EncryptWithWorkers(dst, plaintext []byte, workers int) ([]byte, error) {
	if e.err != nil {
		return nil, e.err
	}
	dstLen := len(dst)
	n, err := encryptedSize(len(plaintext), e.blockSize, e.padding)
	if err != nil {
		return nil, err
	}
	workers, err = manualWorkers(n, e.blockSize, workers)
	if err != nil {
		return nil, err
	}
	ret, out, err := sliceForAppendChecked(dst, plaintext, n)
	if err != nil {
		return nil, err
	}
	written, err := e.encryptInto(out, plaintext, workers)
	if err != nil {
		return nil, err
	}
	return ret[:dstLen+len(written)], nil
}

// SetWorkers настраивает постоянный worker pool для многоблочных операций ECB.
func (e *ECB) SetWorkers(workers int) error {
	return e.parallel.setWorkers(workers)
}

// ResetWorkers возвращает ECB к автоматическому выбору workers.
func (e *ECB) ResetWorkers() {
	e.parallel.resetWorkers()
}

// Close освобождает worker-ресурсы ECB. Объект можно использовать снова.
func (e *ECB) Close() {
	e.parallel.close()
}

// EncryptTo шифрует plaintext в dst без append-роста результата.
func (e *ECB) EncryptTo(dst, plaintext []byte) ([]byte, error) {
	return e.encryptTo(dst, plaintext, 0)
}

// EncryptToWithWorkers шифрует plaintext в dst с заданным числом workers.
// workers должно быть больше 1.
func (e *ECB) EncryptToWithWorkers(dst, plaintext []byte, workers int) ([]byte, error) {
	if e.err != nil {
		return nil, e.err
	}
	n, err := encryptedSize(len(plaintext), e.blockSize, e.padding)
	if err != nil {
		return nil, err
	}
	workers, err = manualWorkers(n, e.blockSize, workers)
	if err != nil {
		return nil, err
	}
	return e.encryptTo(dst, plaintext, workers)
}

func (e *ECB) encryptTo(dst, plaintext []byte, workers int) ([]byte, error) {
	if e.err != nil {
		return nil, e.err
	}
	n, err := encryptedSize(len(plaintext), e.blockSize, e.padding)
	if err != nil {
		return nil, err
	}
	out, err := sliceForWriteChecked(dst, plaintext, n)
	if err != nil {
		return nil, err
	}
	return e.encryptInto(out, plaintext, workers)
}

func (e *ECB) encryptInto(out, plaintext []byte, workers int) ([]byte, error) {
	if e.padding == PaddingNone {
		e.encryptBlocks(out[:len(plaintext)], plaintext, workers)
		return out[:len(plaintext)], nil
	}
	if err := padInto(out, plaintext, e.blockSize, e.padding); err != nil {
		return nil, err
	}
	e.encryptBlocks(out, out, workers)
	return out, nil
}

func (e *ECB) Decrypt(dst, ciphertext []byte) ([]byte, error) {
	if e.err != nil {
		return nil, e.err
	}
	if len(ciphertext)%e.blockSize != 0 {
		return nil, blockLengthError(len(ciphertext))
	}
	dstLen := len(dst)
	ret, out, err := sliceForAppendChecked(dst, ciphertext, len(ciphertext))
	if err != nil {
		return nil, err
	}
	written, err := e.decryptInto(out, ciphertext, 0)
	if err != nil {
		return nil, err
	}
	return ret[:dstLen+len(written)], nil
}

// DecryptWithWorkers работает как Decrypt, но использует заданное число workers
// для независимой обработки блоков. workers должно быть больше 1.
func (e *ECB) DecryptWithWorkers(dst, ciphertext []byte, workers int) ([]byte, error) {
	if e.err != nil {
		return nil, e.err
	}
	if len(ciphertext)%e.blockSize != 0 {
		return nil, blockLengthError(len(ciphertext))
	}
	dstLen := len(dst)
	workers, err := manualWorkers(len(ciphertext), e.blockSize, workers)
	if err != nil {
		return nil, err
	}
	ret, out, err := sliceForAppendChecked(dst, ciphertext, len(ciphertext))
	if err != nil {
		return nil, err
	}
	written, err := e.decryptInto(out, ciphertext, workers)
	if err != nil {
		return nil, err
	}
	return ret[:dstLen+len(written)], nil
}

// DecryptTo расшифровывает ciphertext в dst без append-роста результата.
func (e *ECB) DecryptTo(dst, ciphertext []byte) ([]byte, error) {
	return e.decryptTo(dst, ciphertext, 0)
}

// DecryptToWithWorkers расшифровывает ciphertext в dst с заданным числом workers.
// workers должно быть больше 1.
func (e *ECB) DecryptToWithWorkers(dst, ciphertext []byte, workers int) ([]byte, error) {
	if e.err != nil {
		return nil, e.err
	}
	if len(ciphertext)%e.blockSize != 0 {
		return nil, blockLengthError(len(ciphertext))
	}
	workers, err := manualWorkers(len(ciphertext), e.blockSize, workers)
	if err != nil {
		return nil, err
	}
	return e.decryptTo(dst, ciphertext, workers)
}

func (e *ECB) decryptTo(dst, ciphertext []byte, workers int) ([]byte, error) {
	if e.err != nil {
		return nil, e.err
	}
	if len(ciphertext)%e.blockSize != 0 {
		return nil, blockLengthError(len(ciphertext))
	}
	out, err := sliceForWriteChecked(dst, ciphertext, len(ciphertext))
	if err != nil {
		return nil, err
	}
	return e.decryptInto(out, ciphertext, workers)
}

func (e *ECB) decryptInto(out, ciphertext []byte, workers int) ([]byte, error) {
	e.decryptBlocks(out[:len(ciphertext)], ciphertext, workers)
	if e.padding == PaddingNone {
		return out[:len(ciphertext)], nil
	}
	plaintext, err := unpad(out[:len(ciphertext)], e.blockSize, e.padding)
	if err != nil {
		return nil, err
	}
	return out[:len(plaintext)], nil
}

func (e *ECB) encryptBlocks(dst, src []byte, workers int) {
	if len(src) == 0 {
		return
	}
	if len(src) == e.blockSize {
		e.block.Encrypt(dst[:e.blockSize], src[:e.blockSize])
		return
	}
	workers = e.parallel.workers(len(src), e.blockSize, workers, parallelBlockMinBytes)
	if e.bulk != nil && len(src) >= 4*e.blockSize {
		if workers <= 1 {
			e.bulk.EncryptBlocks(dst, src)
			return
		}
		e.parallel.runOp(len(src), e.blockSize, workers, parallelOpEncryptBlocks, parallelContext{
			bulk:      e.bulk,
			dst:       dst,
			src:       src,
			blockSize: e.blockSize,
		})
		return
	}
	for offset := 0; offset < len(src); offset += e.blockSize {
		e.block.Encrypt(dst[offset:offset+e.blockSize], src[offset:offset+e.blockSize])
	}
}

func (e *ECB) decryptBlocks(dst, src []byte, workers int) {
	if len(src) == 0 {
		return
	}
	if len(src) == e.blockSize {
		e.block.Decrypt(dst[:e.blockSize], src[:e.blockSize])
		return
	}
	workers = e.parallel.workers(len(src), e.blockSize, workers, parallelBlockMinBytes)
	if e.bulk != nil && len(src) >= 4*e.blockSize {
		if workers <= 1 {
			e.bulk.DecryptBlocks(dst, src)
			return
		}
		e.parallel.runOp(len(src), e.blockSize, workers, parallelOpDecryptBlocks, parallelContext{
			bulk:      e.bulk,
			dst:       dst,
			src:       src,
			blockSize: e.blockSize,
		})
		return
	}
	for offset := 0; offset < len(src); offset += e.blockSize {
		e.block.Decrypt(dst[offset:offset+e.blockSize], src[offset:offset+e.blockSize])
	}
}

func (c *CBC) Encrypt(dst, plaintext []byte) ([]byte, error) {
	dstLen := len(dst)
	n, err := encryptedSize(len(plaintext), c.blockSize, c.padding)
	if err != nil {
		return nil, err
	}
	ret, out, err := sliceForAppendChecked(dst, plaintext, n)
	if err != nil {
		return nil, err
	}
	written, err := c.encryptInto(out, plaintext)
	if err != nil {
		return nil, err
	}
	return ret[:dstLen+len(written)], nil
}

// EncryptWithWorkers проверяет workers и шифрует последовательно, потому что
// CBC-шифрование зависит от предыдущего блока ciphertext.
func (c *CBC) EncryptWithWorkers(dst, plaintext []byte, workers int) ([]byte, error) {
	if _, err := manualWorkers(len(plaintext), c.blockSize, workers); err != nil {
		return nil, err
	}
	return c.Encrypt(dst, plaintext)
}

// SetWorkers настраивает постоянный worker pool для CBC-расшифрования.
// CBC-шифрование остаётся последовательным, потому что каждый блок ciphertext
// зависит от предыдущего блока.
func (c *CBC) SetWorkers(workers int) error {
	return c.parallel.setWorkers(workers)
}

// ResetWorkers возвращает CBC-расшифрование к автоматическому выбору workers.
func (c *CBC) ResetWorkers() {
	c.parallel.resetWorkers()
}

// Close освобождает worker-ресурсы CBC. Объект можно использовать снова.
func (c *CBC) Close() {
	c.parallel.close()
}

// EncryptTo шифрует plaintext в dst без append-роста результата.
func (c *CBC) EncryptTo(dst, plaintext []byte) ([]byte, error) {
	n, err := encryptedSize(len(plaintext), c.blockSize, c.padding)
	if err != nil {
		return nil, err
	}
	out, err := sliceForWriteChecked(dst, plaintext, n)
	if err != nil {
		return nil, err
	}
	return c.encryptInto(out, plaintext)
}

func (c *CBC) encryptInto(out, plaintext []byte) ([]byte, error) {
	if c.ivHeap != nil {
		if c.padding == PaddingNone {
			out = out[:len(plaintext)]
			c.encryptExtended(out, plaintext)
		} else if err := padInto(out, plaintext, c.blockSize, c.padding); err != nil {
			return nil, err
		} else {
			c.encryptExtended(out, out)
		}
		return out, nil
	}
	if c.padding == PaddingNone {
		out = out[:len(plaintext)]
		if len(plaintext) == 0 {
			return out, nil
		}
		if len(plaintext) == c.blockSize {
			xorIntoBlock(out[:c.blockSize], plaintext[:c.blockSize], c.iv[:c.blockSize], c.blockSize)
			c.block.Encrypt(out[:c.blockSize], out[:c.blockSize])
			return out, nil
		}
		if c.fast != nil {
			c.fast.EncryptCBC(out, plaintext, c.iv[:c.blockSize])
		} else {
			var prev [16]byte
			copy(prev[:], c.iv[:c.blockSize])
			for offset := 0; offset < len(plaintext); offset += c.blockSize {
				xorIntoBlock(out[offset:offset+c.blockSize], plaintext[offset:offset+c.blockSize], prev[:c.blockSize], c.blockSize)
				c.block.Encrypt(out[offset:offset+c.blockSize], out[offset:offset+c.blockSize])
				copy(prev[:], out[offset:offset+c.blockSize])
			}
		}
		return out, nil
	}
	if err := padInto(out, plaintext, c.blockSize, c.padding); err != nil {
		return nil, err
	}
	if len(out) == c.blockSize {
		xorIntoBlock(out[:c.blockSize], out[:c.blockSize], c.iv[:c.blockSize], c.blockSize)
		c.block.Encrypt(out[:c.blockSize], out[:c.blockSize])
		return out, nil
	}

	if c.fast != nil {
		c.fast.EncryptCBC(out, out, c.iv[:c.blockSize])
	} else {
		var prev [16]byte
		copy(prev[:], c.iv[:c.blockSize])
		for offset := 0; offset < len(out); offset += c.blockSize {
			xorIntoBlock(out[offset:offset+c.blockSize], out[offset:offset+c.blockSize], prev[:c.blockSize], c.blockSize)
			c.block.Encrypt(out[offset:offset+c.blockSize], out[offset:offset+c.blockSize])
			copy(prev[:], out[offset:offset+c.blockSize])
		}
	}
	return out, nil
}

// EncryptToWithWorkers проверяет workers и шифрует последовательно, потому что
// CBC-шифрование зависит от предыдущего блока ciphertext.
func (c *CBC) EncryptToWithWorkers(dst, plaintext []byte, workers int) ([]byte, error) {
	if _, err := manualWorkers(len(plaintext), c.blockSize, workers); err != nil {
		return nil, err
	}
	return c.EncryptTo(dst, plaintext)
}

func (c *CBC) Decrypt(dst, ciphertext []byte) ([]byte, error) {
	if len(ciphertext)%c.blockSize != 0 {
		return nil, blockLengthError(len(ciphertext))
	}
	dstLen := len(dst)
	ret, out, err := sliceForAppendChecked(dst, ciphertext, len(ciphertext))
	if err != nil {
		return nil, err
	}
	written, err := c.decryptInto(out, ciphertext, 0)
	if err != nil {
		return nil, err
	}
	return ret[:dstLen+len(written)], nil
}

// DecryptWithWorkers работает как Decrypt, но использует заданное число workers
// для безопасного out-of-place CBC-расшифрования. workers должно быть больше 1.
func (c *CBC) DecryptWithWorkers(dst, ciphertext []byte, workers int) ([]byte, error) {
	if len(ciphertext)%c.blockSize != 0 {
		return nil, blockLengthError(len(ciphertext))
	}
	dstLen := len(dst)
	workers, err := manualWorkers(len(ciphertext), c.blockSize, workers)
	if err != nil {
		return nil, err
	}
	ret, out, err := sliceForAppendChecked(dst, ciphertext, len(ciphertext))
	if err != nil {
		return nil, err
	}
	written, err := c.decryptInto(out, ciphertext, workers)
	if err != nil {
		return nil, err
	}
	return ret[:dstLen+len(written)], nil
}

// DecryptTo расшифровывает ciphertext в dst без append-роста результата.
func (c *CBC) DecryptTo(dst, ciphertext []byte) ([]byte, error) {
	return c.decryptTo(dst, ciphertext, 0)
}

// DecryptToWithWorkers расшифровывает ciphertext в dst с заданным числом workers.
// workers должно быть больше 1.
func (c *CBC) DecryptToWithWorkers(dst, ciphertext []byte, workers int) ([]byte, error) {
	if len(ciphertext)%c.blockSize != 0 {
		return nil, blockLengthError(len(ciphertext))
	}
	workers, err := manualWorkers(len(ciphertext), c.blockSize, workers)
	if err != nil {
		return nil, err
	}
	return c.decryptTo(dst, ciphertext, workers)
}

func (c *CBC) decryptTo(dst, ciphertext []byte, workers int) ([]byte, error) {
	if len(ciphertext)%c.blockSize != 0 {
		return nil, blockLengthError(len(ciphertext))
	}
	out, err := sliceForWriteChecked(dst, ciphertext, len(ciphertext))
	if err != nil {
		return nil, err
	}
	return c.decryptInto(out, ciphertext, workers)
}

func (c *CBC) decryptInto(out, ciphertext []byte, workers int) ([]byte, error) {
	out = out[:len(ciphertext)]
	if c.ivHeap != nil {
		c.decryptExtended(out, ciphertext)
	} else if len(ciphertext) == c.blockSize {
		c.block.Decrypt(out[:c.blockSize], ciphertext[:c.blockSize])
		xorIntoBlock(out[:c.blockSize], out[:c.blockSize], c.iv[:c.blockSize], c.blockSize)
	} else if c.bulk != nil && len(ciphertext) >= 4*c.blockSize && !sameStart(out, ciphertext) {
		c.decryptBulk(out, ciphertext, workers)
	} else if c.fast != nil {
		c.fast.DecryptCBC(out, ciphertext, c.iv[:c.blockSize])
	} else {
		for offset := len(ciphertext) - c.blockSize; offset >= 0; offset -= c.blockSize {
			c.block.Decrypt(out[offset:offset+c.blockSize], ciphertext[offset:offset+c.blockSize])
			if offset == 0 {
				xorIntoBlock(out[:c.blockSize], out[:c.blockSize], c.iv[:c.blockSize], c.blockSize)
				break
			}
			xorIntoBlock(out[offset:offset+c.blockSize], out[offset:offset+c.blockSize], ciphertext[offset-c.blockSize:offset], c.blockSize)
		}
	}
	if c.padding == PaddingNone {
		return out, nil
	}
	plaintext, err := unpad(out, c.blockSize, c.padding)
	if err != nil {
		return nil, err
	}
	return out[:len(plaintext)], nil
}

// For m > n, GOST 34.13 shifts the m-bit register by a full block after
// each encryption. The standard m=n path above retains its fast bulk code.
func (c *CBC) encryptExtended(dst, src []byte) {
	bs := c.blockSize
	r := c.register
	copy(r, c.ivHeap)
	var work [16]byte
	for offset := 0; offset < len(src); offset += bs {
		xorInto(work[:bs], src[offset:offset+bs], r[:bs])
		c.block.Encrypt(dst[offset:offset+bs], work[:bs])
		copy(r, r[bs:])
		copy(r[len(r)-bs:], dst[offset:offset+bs])
	}
}

func (c *CBC) decryptExtended(dst, src []byte) {
	bs := c.blockSize
	r := c.register
	copy(r, c.ivHeap)
	var work, saved [16]byte
	for offset := 0; offset < len(src); offset += bs {
		copy(saved[:bs], src[offset:offset+bs])
		c.block.Decrypt(work[:bs], saved[:bs])
		xorInto(dst[offset:offset+bs], work[:bs], r[:bs])
		copy(r, r[bs:])
		copy(r[len(r)-bs:], saved[:bs])
	}
}

func (c *CBC) decryptBulk(out, ciphertext []byte, workers int) {
	workers = c.parallel.workers(len(ciphertext), c.blockSize, workers, parallelBlockMinBytes)
	if workers <= 1 {
		c.bulk.DecryptBlocks(out, ciphertext)
		xorCBCDecryptedChunk(out, ciphertext, c.iv[:c.blockSize], c.blockSize)
		return
	}
	c.parallel.runOp(len(ciphertext), c.blockSize, workers, parallelOpCBCDecrypt, parallelContext{
		bulk:      c.bulk,
		dst:       out,
		src:       ciphertext,
		iv:        c.iv[:c.blockSize],
		blockSize: c.blockSize,
	})
}

func blockLengthError(n int) error {
	return &invalidInputError{msg: "block-aligned input", n: n}
}

type invalidInputError struct {
	msg string
	n   int
}

func (e *invalidInputError) Error() string {
	return ErrInvalidInput.Error() + ": " + e.msg + " length " + itoa(e.n)
}

func (e *invalidInputError) Unwrap() error { return ErrInvalidInput }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	u := n
	if u < 0 {
		u = -u
	}
	for u > 0 {
		i--
		buf[i] = byte('0' + u%10)
		u /= 10
	}
	if n < 0 {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

func sliceForAppendChecked(dst, src []byte, n int) (head, tail []byte, err error) {
	head, tail = sliceForAppend(dst, n)
	if inexactOverlap(tail, src) {
		return nil, nil, ErrInvalidOverlap
	}
	return head, tail, nil
}

func sliceForWriteChecked(dst, src []byte, n int) ([]byte, error) {
	if len(dst) < n {
		return nil, &invalidInputError{msg: "output buffer", n: len(dst)}
	}
	out := dst[:n]
	if inexactOverlap(out, src) {
		return nil, ErrInvalidOverlap
	}
	return out, nil
}

func encryptedSize(n, blockSize int, padding Padding) (int, error) {
	if padding == PaddingNone {
		if n%blockSize != 0 {
			return 0, blockLengthError(n)
		}
		return n, nil
	}
	return paddedSize(n, blockSize, padding)
}

func inexactOverlap(x, y []byte) bool {
	if len(x) == 0 || len(y) == 0 {
		return false
	}
	if &x[0] == &y[0] {
		return false
	}
	return anyOverlap(x, y)
}

func sameStart(x, y []byte) bool {
	if len(x) == 0 || len(y) == 0 {
		return false
	}
	return &x[0] == &y[0]
}

func anyOverlap(x, y []byte) bool {
	if len(x) == 0 || len(y) == 0 {
		return false
	}
	x0 := uintptr(unsafe.Pointer(&x[0]))
	y0 := uintptr(unsafe.Pointer(&y[0]))
	return x0 <= y0+uintptr(len(y))-1 && y0 <= x0+uintptr(len(x))-1
}

func xorInto(dst, a, b []byte) {
	for i := range dst {
		dst[i] = a[i] ^ b[i]
	}
}
