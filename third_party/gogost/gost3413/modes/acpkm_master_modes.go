package modes

import (
	"crypto/cipher"
	"crypto/hmac"

	"gitverse.ru/uzer_007/gogost/v3/internal/errx"
)

// ACPKM-Master modes derive a fresh data key for every section. The initial
// key is used only to derive section material, never to encrypt message data.
// The prepared objects cache section cipher schedules and are not safe for
// concurrent use. IVs and counter nonces must be unique for each message.

type masterSection struct {
	block cipher.Block
	fast  ctrCounterBlock
	extra [16]byte
}

type masterCore struct {
	newCipher    func([]byte) (cipher.Block, error)
	master       cipher.Block
	sections     []masterSection
	counter      [16]byte
	blockSize    int
	sectionSize  int
	frequency    int
	materialSize int
	produced     int
}

func newMasterCore(key []byte, newCipher func([]byte) (cipher.Block, error), sectionSize, frequency, extraSize int) (*masterCore, error) {
	if len(key) != 32 || newCipher == nil {
		return nil, ErrInvalidKeySize
	}
	initial, err := newCipher(key)
	if err != nil {
		return nil, err
	}
	bs := initial.BlockSize()
	if err := validateBlockSize(bs); err != nil {
		return nil, err
	}
	d := 32 + extraSize
	if extraSize != 0 && extraSize != bs {
		return nil, ErrInvalidInput
	}
	if sectionSize <= 0 || sectionSize%bs != 0 || frequency < d || frequency%d != 0 || frequency%bs != 0 {
		return nil, errx.Wrap(ErrInvalidInput, "некорректные параметры ACPKM-Master")
	}
	c := &masterCore{newCipher: newCipher, master: initial, blockSize: bs, sectionSize: sectionSize, frequency: frequency, materialSize: d}
	for i := 0; i < bs/2; i++ {
		c.counter[i] = 0xff
	}
	return c, nil
}

func (c *masterCore) ensureSections(n int) error {
	for len(c.sections) < n {
		var material [48]byte
		for i := 0; i < c.materialSize; i += c.blockSize {
			if c.produced != 0 && c.produced%c.frequency == 0 {
				var next [32]byte
				deriveACPKMKeyInto(next[:], c.master)
				var err error
				c.master, err = c.newCipher(next[:])
				clear(next[:])
				if err != nil {
					clear(material[:])
					return err
				}
			}
			c.master.Encrypt(material[i:i+c.blockSize], c.counter[:c.blockSize])
			incCounter(c.counter[c.blockSize/2 : c.blockSize])
			c.produced += c.blockSize
		}
		block, err := c.newCipher(material[:32])
		if err != nil {
			clear(material[:])
			return err
		}
		section := masterSection{block: block}
		section.fast, _ = block.(ctrCounterBlock)
		copy(section.extra[:], material[32:c.materialSize])
		clear(material[:])
		c.sections = append(c.sections, section)
	}
	return nil
}

func (c *masterCore) sectionsFor(n int) error {
	if n == 0 {
		return nil
	}
	return c.ensureSections(1 + (n-1)/c.sectionSize)
}

func (e engine) master(sectionSize, frequency, extraSize int) (*masterCore, error) {
	if e.algorithm != AlgorithmKuznechik && e.algorithm != AlgorithmMagma {
		return nil, ErrInvalidAlgorithm
	}
	return newMasterCore(e.key, func(key []byte) (cipher.Block, error) {
		return newBlock(e.algorithm, key, nil)
	}, sectionSize, frequency, extraSize)
}

// CTRACPKMMaster is the reusable RFC 8645 section 6.3.2 counter mode.
type CTRACPKMMaster struct {
	core *masterCore
	iv   [16]byte
	ctr  [16]byte
	buf  [16]byte
}

func (e engine) ctrACPKMMaster(iv []byte, sectionSize, frequency int) (*CTRACPKMMaster, error) {
	if len(iv) != e.blockSize/2 {
		return nil, ErrInvalidIVSize
	}
	core, err := e.master(sectionSize, frequency, 0)
	if err != nil {
		return nil, err
	}
	m := &CTRACPKMMaster{core: core}
	copy(m.iv[:], iv)
	return m, nil
}

func (k *Kuznechik) CTRACPKMMaster(iv []byte, sectionSize, masterFrequency int) (*CTRACPKMMaster, error) {
	return k.e.ctrACPKMMaster(iv, sectionSize, masterFrequency)
}
func (m *Magma) CTRACPKMMaster(iv []byte, sectionSize, masterFrequency int) (*CTRACPKMMaster, error) {
	return m.e.ctrACPKMMaster(iv, sectionSize, masterFrequency)
}

// XORKeyStreamAt processes an independent chunk at a byte offset. Exact
// in-place use is supported; partial overlap is rejected.
func (m *CTRACPKMMaster) XORKeyStreamAt(dst, src []byte, offset int) ([]byte, error) {
	if m == nil || m.core == nil || offset < 0 || offset > int(^uint(0)>>1)-len(src) {
		return nil, ErrInvalidInput
	}
	out, err := sliceForWriteChecked(dst, src, len(src))
	if err != nil || len(src) == 0 {
		return out, err
	}
	c := m.core
	if err := c.ensureSections(1 + (offset+len(src)-1)/c.sectionSize); err != nil {
		return nil, err
	}
	for pos, done := offset, 0; done < len(src); {
		section := pos / c.sectionSize
		n := min(len(src)-done, c.sectionSize-pos%c.sectionSize)
		copy(m.ctr[:c.blockSize/2], m.iv[:c.blockSize/2])
		clear(m.ctr[c.blockSize/2 : c.blockSize])
		addCounter(m.ctr[c.blockSize/2:c.blockSize], pos/c.blockSize)
		in, target := src[done:done+n], out[done:done+n]
		if partial := pos % c.blockSize; partial != 0 {
			c.sections[section].block.Encrypt(m.buf[:c.blockSize], m.ctr[:c.blockSize])
			first := min(n, c.blockSize-partial)
			for i := 0; i < first; i++ {
				target[i] = in[i] ^ m.buf[partial+i]
			}
			in, target = in[first:], target[first:]
			incCounter(m.ctr[c.blockSize/2 : c.blockSize])
		}
		if len(in) != 0 {
			s := c.sections[section]
			xorCTR(target, in, s.block, s.fast, m.ctr[:c.blockSize], m.buf[:c.blockSize])
		}
		pos += n
		done += n
	}
	return out, nil
}

func (m *CTRACPKMMaster) XORKeyStreamTo(dst, src []byte) ([]byte, error) {
	return m.XORKeyStreamAt(dst, src, 0)
}
func (m *CTRACPKMMaster) XORKeyStream(dst, src []byte) ([]byte, error) {
	ret, tail, err := sliceForAppendChecked(dst, src, len(src))
	if err != nil {
		return nil, err
	}
	if _, err := m.XORKeyStreamTo(tail, src); err != nil {
		return nil, err
	}
	return ret, nil
}
func (m *CTRACPKMMaster) Encrypt(dst, src []byte) ([]byte, error) { return m.XORKeyStream(dst, src) }
func (m *CTRACPKMMaster) Decrypt(dst, src []byte) ([]byte, error) { return m.XORKeyStream(dst, src) }
func (m *CTRACPKMMaster) EncryptTo(dst, src []byte) ([]byte, error) {
	return m.XORKeyStreamTo(dst, src)
}
func (m *CTRACPKMMaster) DecryptTo(dst, src []byte) ([]byte, error) {
	return m.XORKeyStreamTo(dst, src)
}

// CBCACPKMMaster is RFC 8645 section 6.3.4, with no implicit padding.
type CBCACPKMMaster struct {
	core *masterCore
	iv   [16]byte
}

func (e engine) cbcACPKMMaster(iv []byte, sectionSize, frequency int) (*CBCACPKMMaster, error) {
	if len(iv) != e.blockSize {
		return nil, ErrInvalidIVSize
	}
	core, err := e.master(sectionSize, frequency, 0)
	if err != nil {
		return nil, err
	}
	m := &CBCACPKMMaster{core: core}
	copy(m.iv[:], iv)
	return m, nil
}

func (k *Kuznechik) CBCACPKMMaster(iv []byte, sectionSize, masterFrequency int) (*CBCACPKMMaster, error) {
	return k.e.cbcACPKMMaster(iv, sectionSize, masterFrequency)
}
func (m *Magma) CBCACPKMMaster(iv []byte, sectionSize, masterFrequency int) (*CBCACPKMMaster, error) {
	return m.e.cbcACPKMMaster(iv, sectionSize, masterFrequency)
}

func (m *CBCACPKMMaster) cryptTo(dst, src []byte, decrypt bool) ([]byte, error) {
	if m == nil || m.core == nil || len(src) == 0 || len(src)%m.core.blockSize != 0 {
		return nil, ErrInvalidInput
	}
	out, err := sliceForWriteChecked(dst, src, len(src))
	if err != nil {
		return nil, err
	}
	c := m.core
	if err := c.sectionsFor(len(src)); err != nil {
		return nil, err
	}
	bs := c.blockSize
	var previous, work, ciphertext [16]byte
	copy(previous[:bs], m.iv[:bs])
	for pos := 0; pos < len(src); pos += bs {
		block := c.sections[pos/c.sectionSize].block
		if decrypt {
			copy(ciphertext[:bs], src[pos:pos+bs])
			block.Decrypt(work[:bs], ciphertext[:bs])
			xorInto(out[pos:pos+bs], work[:bs], previous[:bs])
			copy(previous[:bs], ciphertext[:bs])
		} else {
			xorInto(work[:bs], src[pos:pos+bs], previous[:bs])
			block.Encrypt(out[pos:pos+bs], work[:bs])
			copy(previous[:bs], out[pos:pos+bs])
		}
	}
	return out, nil
}

func (m *CBCACPKMMaster) EncryptTo(dst, plaintext []byte) ([]byte, error) {
	return m.cryptTo(dst, plaintext, false)
}
func (m *CBCACPKMMaster) DecryptTo(dst, ciphertext []byte) ([]byte, error) {
	return m.cryptTo(dst, ciphertext, true)
}
func (m *CBCACPKMMaster) Encrypt(dst, plaintext []byte) ([]byte, error) {
	ret, tail, err := sliceForAppendChecked(dst, plaintext, len(plaintext))
	if err != nil {
		return nil, err
	}
	if _, err := m.EncryptTo(tail, plaintext); err != nil {
		return nil, err
	}
	return ret, nil
}
func (m *CBCACPKMMaster) Decrypt(dst, ciphertext []byte) ([]byte, error) {
	ret, tail, err := sliceForAppendChecked(dst, ciphertext, len(ciphertext))
	if err != nil {
		return nil, err
	}
	if _, err := m.DecryptTo(tail, ciphertext); err != nil {
		return nil, err
	}
	return ret, nil
}

// CFBACPKMMaster is RFC 8645 section 6.3.5, with full-block feedback.
type CFBACPKMMaster struct {
	core *masterCore
	iv   [16]byte
}

func (e engine) cfbACPKMMaster(iv []byte, sectionSize, frequency int) (*CFBACPKMMaster, error) {
	if len(iv) != e.blockSize {
		return nil, ErrInvalidIVSize
	}
	core, err := e.master(sectionSize, frequency, 0)
	if err != nil {
		return nil, err
	}
	m := &CFBACPKMMaster{core: core}
	copy(m.iv[:], iv)
	return m, nil
}

func (k *Kuznechik) CFBACPKMMaster(iv []byte, sectionSize, masterFrequency int) (*CFBACPKMMaster, error) {
	return k.e.cfbACPKMMaster(iv, sectionSize, masterFrequency)
}
func (m *Magma) CFBACPKMMaster(iv []byte, sectionSize, masterFrequency int) (*CFBACPKMMaster, error) {
	return m.e.cfbACPKMMaster(iv, sectionSize, masterFrequency)
}

func (m *CFBACPKMMaster) cryptTo(dst, src []byte, decrypt bool) ([]byte, error) {
	if m == nil || m.core == nil {
		return nil, ErrInvalidInput
	}
	out, err := sliceForWriteChecked(dst, src, len(src))
	if err != nil || len(src) == 0 {
		return out, err
	}
	c := m.core
	if err := c.sectionsFor(len(src)); err != nil {
		return nil, err
	}
	bs := c.blockSize
	var previous, gamma, ciphertext [16]byte
	copy(previous[:bs], m.iv[:bs])
	for pos := 0; pos < len(src); pos += bs {
		c.sections[pos/c.sectionSize].block.Encrypt(gamma[:bs], previous[:bs])
		n := min(bs, len(src)-pos)
		if decrypt {
			copy(ciphertext[:n], src[pos:pos+n])
		}
		for i := 0; i < n; i++ {
			out[pos+i] = src[pos+i] ^ gamma[i]
		}
		if decrypt {
			copy(previous[:n], ciphertext[:n])
		} else {
			copy(previous[:n], out[pos:pos+n])
		}
	}
	return out, nil
}

func (m *CFBACPKMMaster) EncryptTo(dst, plaintext []byte) ([]byte, error) {
	return m.cryptTo(dst, plaintext, false)
}
func (m *CFBACPKMMaster) DecryptTo(dst, ciphertext []byte) ([]byte, error) {
	return m.cryptTo(dst, ciphertext, true)
}
func (m *CFBACPKMMaster) Encrypt(dst, plaintext []byte) ([]byte, error) {
	ret, tail, err := sliceForAppendChecked(dst, plaintext, len(plaintext))
	if err != nil {
		return nil, err
	}
	if _, err := m.EncryptTo(tail, plaintext); err != nil {
		return nil, err
	}
	return ret, nil
}
func (m *CFBACPKMMaster) Decrypt(dst, ciphertext []byte) ([]byte, error) {
	ret, tail, err := sliceForAppendChecked(dst, ciphertext, len(ciphertext))
	if err != nil {
		return nil, err
	}
	if _, err := m.DecryptTo(tail, ciphertext); err != nil {
		return nil, err
	}
	return ret, nil
}

// OMACACPKMMaster is RFC 8645 section 6.3.6. It derives the MAC subkey
// independently with each section key, unlike ordinary OMAC/CMAC.
type OMACACPKMMaster struct {
	core    *masterCore
	tagSize int
}

func (e engine) omacACPKMMaster(sectionSize, frequency, tagSize int) (*OMACACPKMMaster, error) {
	if tagSize == 0 {
		tagSize = e.blockSize
	}
	if tagSize < 1 || tagSize > e.blockSize {
		return nil, ErrInvalidTagSize
	}
	core, err := e.master(sectionSize, frequency, e.blockSize)
	if err != nil {
		return nil, err
	}
	return &OMACACPKMMaster{core: core, tagSize: tagSize}, nil
}

func (k *Kuznechik) OMACACPKMMaster(sectionSize, masterFrequency, tagSize int) (*OMACACPKMMaster, error) {
	return k.e.omacACPKMMaster(sectionSize, masterFrequency, tagSize)
}
func (m *Magma) OMACACPKMMaster(sectionSize, masterFrequency, tagSize int) (*OMACACPKMMaster, error) {
	return m.e.omacACPKMMaster(sectionSize, masterFrequency, tagSize)
}

func (m *OMACACPKMMaster) Sum(dst, data []byte) []byte {
	if m == nil || m.core == nil {
		return nil
	}
	c := m.core
	// Empty data is treated as one padded block under the first section key.
	sections := 1
	if len(data) != 0 {
		sections += (len(data) - 1) / c.sectionSize
	}
	if err := c.ensureSections(sections); err != nil {
		return nil
	}
	bs := c.blockSize
	var state, final, subkey [16]byte
	fullBeforeFinal := 0
	if len(data) > 0 && len(data)%bs == 0 {
		fullBeforeFinal = len(data)/bs - 1
	} else {
		fullBeforeFinal = len(data) / bs
	}
	for i := 0; i < fullBeforeFinal; i++ {
		xorInto(state[:bs], state[:bs], data[i*bs:(i+1)*bs])
		c.sections[(i*bs)/c.sectionSize].block.Encrypt(state[:bs], state[:bs])
	}
	lastOffset := fullBeforeFinal * bs
	last := data[lastOffset:]
	copy(final[:bs], last)
	section := c.sections[lastOffset/c.sectionSize]
	if len(last) == bs {
		copy(subkey[:bs], section.extra[:bs])
	} else {
		final[len(last)] = 0x80
		doubleSubkeyInto(subkey[:bs], section.extra[:bs])
	}
	xorInto(state[:bs], state[:bs], final[:bs])
	xorInto(state[:bs], state[:bs], subkey[:bs])
	section.block.Encrypt(state[:bs], state[:bs])
	ret, tail := sliceForAppend(dst, m.tagSize)
	copy(tail, state[:m.tagSize])
	return ret
}

func (m *OMACACPKMMaster) Verify(data, tag []byte) bool {
	if m == nil || len(tag) != m.tagSize {
		return false
	}
	return hmac.Equal(m.Sum(nil, data), tag)
}
