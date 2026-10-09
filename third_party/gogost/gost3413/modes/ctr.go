package modes

import (
	"crypto/cipher"

	"gitverse.ru/uzer_007/gogost/v3/gost28147"
	"gitverse.ru/uzer_007/gogost/v3/internal/errx"
)

var acpkmD = [32]byte{
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
	0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
	0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
}

// CTRACPKM представляет подготовленный CTR-ACPKM stream с ленивым кэшем ключей секций.
type CTRACPKM struct {
	algorithm   Algorithm
	key         []byte
	sbox        *gost28147.Sbox
	blockSize   int
	iv          [16]byte
	sectionSize int
	counter     [16]byte
	gamma       [16]byte
	blocks      []cipher.Block
	fastBlocks  []ctrCounterBlock
	parallel    parallelState
}

func normalizeCTRIVInto(counter, iv []byte) {
	switch len(iv) {
	case len(counter):
		copy(counter, iv)
	case len(counter) / 2:
		clear(counter)
		copy(counter, iv)
	default:
		clear(counter)
	}
}

func incCounter(counter []byte) {
	for i := len(counter) - 1; i >= 0; i-- {
		counter[i]++
		if counter[i] != 0 {
			return
		}
	}
}

type ctrCounterBlock interface {
	XORKeyStreamCTRCounter(dst, src, counter []byte)
}

func xorCTR(dst, src []byte, block blockCipher, fast ctrCounterBlock, counter, gamma []byte) {
	if fast != nil {
		fast.XORKeyStreamCTRCounter(dst, src, counter)
		return
	}
	blockSize := block.BlockSize()
	for len(src) > 0 {
		block.Encrypt(gamma, counter)
		n := min(blockSize, len(src))
		for i := 0; i < n; i++ {
			dst[i] = src[i] ^ gamma[i]
		}
		incCounter(counter[blockSize/2:])
		dst = dst[n:]
		src = src[n:]
	}
}

func (c *CTRACPKM) Encrypt(dst, plaintext []byte) ([]byte, error) {
	return c.XORKeyStream(dst, plaintext)
}

func (c *CTRACPKM) Decrypt(dst, ciphertext []byte) ([]byte, error) {
	return c.XORKeyStream(dst, ciphertext)
}

func (c *CTRACPKM) EncryptTo(dst, plaintext []byte) ([]byte, error) {
	return c.XORKeyStreamTo(dst, plaintext)
}

func (c *CTRACPKM) DecryptTo(dst, ciphertext []byte) ([]byte, error) {
	return c.XORKeyStreamTo(dst, ciphertext)
}

func (c *CTRACPKM) EncryptWithWorkers(dst, plaintext []byte, workers int) ([]byte, error) {
	return c.XORKeyStreamWithWorkers(dst, plaintext, workers)
}

// SetWorkers настраивает постоянный worker pool для CTR-ACPKM stream.
func (c *CTRACPKM) SetWorkers(workers int) error {
	return c.parallel.setWorkers(workers)
}

// ResetWorkers возвращает CTR-ACPKM к автоматическому выбору workers.
func (c *CTRACPKM) ResetWorkers() {
	c.parallel.resetWorkers()
}

// Close освобождает worker-ресурсы CTR-ACPKM. Объект можно использовать снова.
func (c *CTRACPKM) Close() {
	c.parallel.close()
}

func (c *CTRACPKM) DecryptWithWorkers(dst, ciphertext []byte, workers int) ([]byte, error) {
	return c.XORKeyStreamWithWorkers(dst, ciphertext, workers)
}

func (c *CTRACPKM) EncryptToWithWorkers(dst, plaintext []byte, workers int) ([]byte, error) {
	return c.XORKeyStreamToWithWorkers(dst, plaintext, workers)
}

func (c *CTRACPKM) DecryptToWithWorkers(dst, ciphertext []byte, workers int) ([]byte, error) {
	return c.XORKeyStreamToWithWorkers(dst, ciphertext, workers)
}

func (c *CTRACPKM) XORKeyStream(dst, src []byte) ([]byte, error) {
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
// число workers для независимых диапазонов секций CTR-ACPKM. workers должно быть больше 1.
func (c *CTRACPKM) XORKeyStreamWithWorkers(dst, src []byte, workers int) ([]byte, error) {
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
func (c *CTRACPKM) XORKeyStreamTo(dst, src []byte) ([]byte, error) {
	return c.xorKeyStreamTo(dst, src, 0)
}

// XORKeyStreamAt applies CTR-ACPKM at a byte offset from the start of the
// message. It permits processing independently sized chunks without retaining
// the whole plaintext or ciphertext. Calls on the same object are not concurrent.
func (c *CTRACPKM) XORKeyStreamAt(dst, src []byte, offset int) ([]byte, error) {
	if c == nil || offset < 0 || offset > int(^uint(0)>>1)-len(src) {
		return nil, ErrInvalidInput
	}
	out, err := sliceForWriteChecked(dst, src, len(src))
	if err != nil || len(src) == 0 {
		return out, err
	}
	if err := c.ensureSections((offset+len(src)-1)/c.sectionSize + 1); err != nil {
		return nil, err
	}
	counterForOffset(c.counter[:c.blockSize], c.iv[:c.blockSize], c.blockSize, offset/c.blockSize)
	position := offset
	for consumed := 0; consumed < len(src); {
		section := position / c.sectionSize
		n := min(len(src)-consumed, c.sectionSize-position%c.sectionSize)
		input, output := src[consumed:consumed+n], out[consumed:consumed+n]
		if partial := position % c.blockSize; partial != 0 {
			c.blocks[section].Encrypt(c.gamma[:c.blockSize], c.counter[:c.blockSize])
			first := min(n, c.blockSize-partial)
			for i := 0; i < first; i++ {
				output[i] = input[i] ^ c.gamma[partial+i]
			}
			input, output = input[first:], output[first:]
			incCounter(c.counter[c.blockSize/2 : c.blockSize])
		}
		if len(input) > 0 {
			xorCTR(output, input, c.blocks[section], c.fastBlocks[section], c.counter[:c.blockSize], c.gamma[:c.blockSize])
		}
		position += n
		consumed += n
	}
	return out, nil
}

// XORKeyStreamToWithWorkers применяет XOR src к dst с заданным числом workers.
// workers должно быть больше 1.
func (c *CTRACPKM) XORKeyStreamToWithWorkers(dst, src []byte, workers int) ([]byte, error) {
	workers, err := manualWorkers(len(src), c.blockSize, workers)
	if err != nil {
		return nil, err
	}
	return c.xorKeyStreamTo(dst, src, workers)
}

func (c *CTRACPKM) xorKeyStreamTo(dst, src []byte, workers int) ([]byte, error) {
	out, err := sliceForWriteChecked(dst, src, len(src))
	if err != nil {
		return nil, err
	}
	return c.xorKeyStreamInto(out, src, workers)
}

func (c *CTRACPKM) xorKeyStreamInto(out, src []byte, workers int) ([]byte, error) {
	out = out[:len(src)]
	if len(src) == 0 {
		return out, nil
	}
	sections := (len(src) + c.sectionSize - 1) / c.sectionSize
	if err := c.ensureSections(sections); err != nil {
		return nil, err
	}
	if len(src) <= c.blockSize {
		normalizeCTRIVInto(c.counter[:c.blockSize], c.iv[:c.blockSize])
		c.blocks[0].Encrypt(c.gamma[:c.blockSize], c.counter[:c.blockSize])
		xorOneBlockOrPartial(out, src, c.gamma[:c.blockSize], len(src))
		return out, nil
	}
	workers = c.parallel.workers(len(src), c.blockSize, workers, parallelStreamMinBytes)
	if workers > 1 {
		c.xorKeyStreamParallel(out, src, sections, workers)
		return out, nil
	}

	normalizeCTRIVInto(c.counter[:c.blockSize], c.iv[:c.blockSize])
	for offset := 0; offset < len(src); {
		sectionLen := min(c.sectionSize, len(src)-offset)
		section := offset / c.sectionSize
		block := c.blocks[section]
		fast := c.fastBlocks[section]
		xorCTR(out[offset:offset+sectionLen], src[offset:offset+sectionLen], block, fast, c.counter[:c.blockSize], c.gamma[:c.blockSize])
		offset += sectionLen
	}
	return out, nil
}

func (c *CTRACPKM) xorKeyStreamParallel(out, src []byte, sections, workers int) {
	if workers > sections {
		workers = sections
	}
	if workers <= 1 {
		normalizeCTRIVInto(c.counter[:c.blockSize], c.iv[:c.blockSize])
		for offset := 0; offset < len(src); {
			sectionLen := min(c.sectionSize, len(src)-offset)
			section := offset / c.sectionSize
			xorCTR(out[offset:offset+sectionLen], src[offset:offset+sectionLen], c.blocks[section], c.fastBlocks[section], c.counter[:c.blockSize], c.gamma[:c.blockSize])
			offset += sectionLen
		}
		return
	}

	c.parallel.runUnitsOp(sections, workers, parallelOpCTRACPKM, parallelContext{
		dst:       out,
		src:       src,
		blockSize: c.blockSize,
		acpkm:     c,
	})
}

// PrecomputeSections готовит кэш ключей секций CTR-ACPKM для данных до maxBytes.
// Это убирает задержку первой выработки ключей из последующих операций.
func (c *CTRACPKM) PrecomputeSections(maxBytes int) error {
	if maxBytes < 0 {
		return errx.Wrap(ErrInvalidInput, "отрицательный размер прогрева "+errx.Int(maxBytes))
	}
	if maxBytes == 0 {
		return nil
	}
	return c.ensureSections((maxBytes + c.sectionSize - 1) / c.sectionSize)
}

func (c *CTRACPKM) ensureSections(n int) error {
	if n > cap(c.blocks) {
		blocks := make([]cipher.Block, len(c.blocks), n)
		copy(blocks, c.blocks)
		c.blocks = blocks
	}
	if n > cap(c.fastBlocks) {
		fastBlocks := make([]ctrCounterBlock, len(c.fastBlocks), n)
		copy(fastBlocks, c.fastBlocks)
		c.fastBlocks = fastBlocks
	}
	for len(c.blocks) < n {
		prev := c.blocks[len(c.blocks)-1]
		var nextKey [32]byte
		deriveACPKMKeyInto(nextKey[:len(c.key)], prev)
		nextBlock, err := newBlock(c.algorithm, nextKey[:len(c.key)], c.sbox)
		if err != nil {
			return err
		}
		fast, _ := nextBlock.(ctrCounterBlock)
		c.blocks = append(c.blocks, nextBlock)
		c.fastBlocks = append(c.fastBlocks, fast)
	}
	return nil
}

func deriveACPKMKeyInto(out []byte, block cipher.Block) {
	blockSize := block.BlockSize()
	var buf [16]byte
	written := 0
	for offset := 0; written < len(out); offset += blockSize {
		block.Encrypt(buf[:blockSize], acpkmD[offset:offset+blockSize])
		written += copy(out[written:], buf[:blockSize])
	}
}
