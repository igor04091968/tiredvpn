// Package modes предоставляет подготовленные высокоуровневые объекты режимов
// ГОСТ Р 34.13 для ГОСТ 28147-89, Магмы и Кузнечика.
//
// Создайте engine выбранного алгоритма один раз, а затем получайте из него
// переиспользуемые объекты режимов. Режимы хранят расписание шифра, шаблон IV и
// небольшие рабочие буферы, поэтому повторные вызовы обходятся без разбора
// конфигурации и повторной инициализации блока. Объекты режимов намеренно не
// являются goroutine-safe; для внешней параллельной обработки создавайте
// отдельный объект на worker.
package modes

import (
	"crypto/cipher"
	"errors"

	"gitverse.ru/uzer_007/gogost/v3/gost28147"
	"gitverse.ru/uzer_007/gogost/v3/gost3412128"
	"gitverse.ru/uzer_007/gogost/v3/gost341264"
	"gitverse.ru/uzer_007/gogost/v3/internal/errx"
)

const DefaultACPKMSectionSize = 1024

var (
	ErrInvalidAlgorithm = errors.New("gogost/gost3413/modes: Некорректный алгоритм")
	ErrInvalidKeySize   = errors.New("gogost/gost3413/modes: Некорректный размер ключа")
	ErrInvalidMode      = errors.New("gogost/gost3413/modes: Некорректный режим")
	ErrInvalidPadding   = errors.New("gogost/gost3413/modes: Некорректный padding")
	ErrInvalidIVSize    = errors.New("gogost/gost3413/modes: Некорректный размер IV")
	ErrInvalidTagSize   = errors.New("gogost/gost3413/modes: Некорректный размер тега")
	ErrInvalidBlockSize = errors.New("gogost/gost3413/modes: Некорректный размер блока")
	ErrInvalidInput     = errors.New("gogost/gost3413/modes: Некорректный ввод")
	ErrInvalidOverlap   = errors.New("gogost/gost3413/modes: Некорректное пересечение буферов")
	ErrAuthFailed       = errors.New("gogost/gost3413/modes: Ошибка аутентификации")
)

type Algorithm uint8

const (
	AlgorithmUnknown Algorithm = iota
	AlgorithmMagma
	AlgorithmKuznechik
	AlgorithmGOST28147
)

type Mode uint8

const (
	ModeUnknown Mode = iota
	ModeECB
	ModeCBC
	ModeCFB
	ModeOFB
	ModeCTR
	ModeCTRACPKM
	ModeMAC
	ModeMGM
)

type Padding uint8

const (
	PaddingDefault Padding = iota
	PaddingNone
	Padding1
	Padding2
	Padding3
)

// Kuznechik представляет подготовленный 128-битный блочный шифр ГОСТ Р 34.12-2015.
type Kuznechik struct {
	e engine
}

// Magma представляет подготовленный 64-битный блочный шифр ГОСТ Р 34.12-2015.
type Magma struct {
	e engine
}

// GOST28147 представляет подготовленный 64-битный блочный шифр ГОСТ 28147-89.
type GOST28147 struct {
	e engine
}

type engine struct {
	algorithm Algorithm
	block     cipher.Block
	bulk      blockBulkCipher
	cbc       cbcCipher
	feedback  feedbackCipher
	ctr       ctrCounterBlock
	key       []byte
	sbox      *gost28147.Sbox
	blockSize int
}

func newEngine(algorithm Algorithm, block cipher.Block, key []byte, sbox *gost28147.Sbox, blockSize int) engine {
	e := engine{
		algorithm: algorithm,
		block:     block,
		key:       key,
		sbox:      sbox,
		blockSize: blockSize,
	}
	e.bulk, _ = block.(blockBulkCipher)
	e.cbc, _ = block.(cbcCipher)
	e.feedback, _ = block.(feedbackCipher)
	e.ctr, _ = block.(ctrCounterBlock)
	return e
}

// NewKuznechik создаёт переиспользуемую фабрику режимов Кузнечика.
func NewKuznechik(key []byte) (*Kuznechik, error) {
	if len(key) != gost3412128.KeySize {
		return nil, errx.Wrap(ErrInvalidKeySize, "длина ключа Кузнечика "+errx.Int(len(key)))
	}
	k := append([]byte(nil), key...)
	return &Kuznechik{e: newEngine(AlgorithmKuznechik, gost3412128.NewCipher(k), k, nil, gost3412128.BlockSize)}, nil
}

// MustKuznechik работает как NewKuznechik, но паникует при неверном вводе.
func MustKuznechik(key []byte) *Kuznechik {
	e, err := NewKuznechik(key)
	if err != nil {
		panic(err)
	}
	return e
}

// NewMagma создаёт переиспользуемую фабрику режимов Магмы.
func NewMagma(key []byte) (*Magma, error) {
	if len(key) != gost341264.KeySize {
		return nil, errx.Wrap(ErrInvalidKeySize, "длина ключа Магмы "+errx.Int(len(key)))
	}
	k := append([]byte(nil), key...)
	return &Magma{e: newEngine(AlgorithmMagma, gost341264.NewCipher(k), k, nil, gost341264.BlockSize)}, nil
}

// MustMagma работает как NewMagma, но паникует при неверном вводе.
func MustMagma(key []byte) *Magma {
	e, err := NewMagma(key)
	if err != nil {
		panic(err)
	}
	return e
}

// NewGOST28147 создаёт переиспользуемую фабрику режимов ГОСТ 28147-89 с заданной S-box.
func NewGOST28147(key []byte, sbox *gost28147.Sbox) (*GOST28147, error) {
	if len(key) != gost28147.KeySize {
		return nil, errx.Wrap(ErrInvalidKeySize, "длина ключа ГОСТ 28147-89 "+errx.Int(len(key)))
	}
	if sbox == nil {
		return nil, errx.Wrap(ErrInvalidInput, "nil S-box ГОСТ 28147-89")
	}
	k := append([]byte(nil), key...)
	return &GOST28147{e: newEngine(AlgorithmGOST28147, gost28147.NewCipher(k, sbox), k, sbox, gost28147.BlockSize)}, nil
}

// NewGOST28147Default создаёт переиспользуемую фабрику режимов ГОСТ 28147-89 с SboxDefault.
func NewGOST28147Default(key []byte) (*GOST28147, error) {
	return NewGOST28147(key, gost28147.SboxDefault)
}

// MustGOST28147 работает как NewGOST28147, но паникует при неверном вводе.
func MustGOST28147(key []byte, sbox *gost28147.Sbox) *GOST28147 {
	e, err := NewGOST28147(key, sbox)
	if err != nil {
		panic(err)
	}
	return e
}

// MustGOST28147Default работает как NewGOST28147Default, но паникует при неверном вводе.
func MustGOST28147Default(key []byte) *GOST28147 {
	e, err := NewGOST28147Default(key)
	if err != nil {
		panic(err)
	}
	return e
}

func (k *Kuznechik) ECB(padding Padding) *ECB { return k.e.ECB(padding) }
func (k *Kuznechik) CBC(iv []byte, padding Padding) (*CBC, error) {
	return k.e.CBC(iv, padding)
}
func (k *Kuznechik) CFB(iv []byte) (*CFB, error) { return k.e.CFB(iv) }
func (k *Kuznechik) CFBN(iv []byte, segmentSize, registerSize int) (*CFB, error) {
	return k.e.CFBN(iv, segmentSize, registerSize)
}
func (k *Kuznechik) OFB(iv []byte) (*OFB, error) { return k.e.OFB(iv) }
func (k *Kuznechik) OFBN(iv []byte, segmentSize, registerSize int) (*OFB, error) {
	return k.e.OFBN(iv, segmentSize, registerSize)
}
func (k *Kuznechik) CTR(iv []byte) (*CTR, error)                   { return k.e.CTR(iv) }
func (k *Kuznechik) CTRN(iv []byte, segmentSize int) (*CTR, error) { return k.e.CTRN(iv, segmentSize) }
func (k *Kuznechik) CTRACPKM(iv []byte, sectionSize int) (*CTRACPKM, error) {
	return k.e.CTRACPKM(iv, sectionSize)
}
func (k *Kuznechik) MAC(tagSize int) (*MAC, error) { return k.e.MAC(tagSize) }
func (k *Kuznechik) MGM(tagSize int) (*MGM, error) { return k.e.MGM(tagSize) }

func (m *Magma) ECB(padding Padding) *ECB { return m.e.ECB(padding) }
func (m *Magma) CBC(iv []byte, padding Padding) (*CBC, error) {
	return m.e.CBC(iv, padding)
}
func (m *Magma) CFB(iv []byte) (*CFB, error) { return m.e.CFB(iv) }
func (m *Magma) CFBN(iv []byte, segmentSize, registerSize int) (*CFB, error) {
	return m.e.CFBN(iv, segmentSize, registerSize)
}
func (m *Magma) OFB(iv []byte) (*OFB, error) { return m.e.OFB(iv) }
func (m *Magma) OFBN(iv []byte, segmentSize, registerSize int) (*OFB, error) {
	return m.e.OFBN(iv, segmentSize, registerSize)
}
func (m *Magma) CTR(iv []byte) (*CTR, error)                   { return m.e.CTR(iv) }
func (m *Magma) CTRN(iv []byte, segmentSize int) (*CTR, error) { return m.e.CTRN(iv, segmentSize) }
func (m *Magma) CTRACPKM(iv []byte, sectionSize int) (*CTRACPKM, error) {
	return m.e.CTRACPKM(iv, sectionSize)
}
func (m *Magma) MAC(tagSize int) (*MAC, error) { return m.e.MAC(tagSize) }
func (m *Magma) MGM(tagSize int) (*MGM, error) { return m.e.MGM(tagSize) }

func (g *GOST28147) ECB(padding Padding) *ECB { return g.e.ECB(padding) }
func (g *GOST28147) CBC(iv []byte, padding Padding) (*CBC, error) {
	return g.e.CBC(iv, padding)
}
func (g *GOST28147) CFB(iv []byte) (*CFB, error) { return g.e.CFB(iv) }
func (g *GOST28147) CFBN(iv []byte, segmentSize, registerSize int) (*CFB, error) {
	return g.e.CFBN(iv, segmentSize, registerSize)
}
func (g *GOST28147) OFB(iv []byte) (*OFB, error) { return g.e.OFB(iv) }
func (g *GOST28147) OFBN(iv []byte, segmentSize, registerSize int) (*OFB, error) {
	return g.e.OFBN(iv, segmentSize, registerSize)
}
func (g *GOST28147) CTR(iv []byte) (*CTR, error)                   { return g.e.CTR(iv) }
func (g *GOST28147) CTRN(iv []byte, segmentSize int) (*CTR, error) { return g.e.CTRN(iv, segmentSize) }
func (g *GOST28147) CTRACPKM(iv []byte, sectionSize int) (*CTRACPKM, error) {
	return g.e.CTRACPKM(iv, sectionSize)
}
func (g *GOST28147) MAC(tagSize int) (*MAC, error) { return g.e.MAC(tagSize) }
func (g *GOST28147) MGM(tagSize int) (*MGM, error) { return g.e.MGM(tagSize) }

func (e engine) ECB(padding Padding) *ECB {
	padding, err := normalizeBlockPadding(padding)
	return &ECB{
		block:     e.block,
		bulk:      e.bulk,
		blockSize: e.blockSize,
		padding:   padding,
		err:       err,
	}
}

func (e engine) CBC(iv []byte, padding Padding) (*CBC, error) {
	padding, err := normalizeBlockPadding(padding)
	if err != nil {
		return nil, err
	}
	if len(iv) < e.blockSize || len(iv)%e.blockSize != 0 {
		return nil, errx.Wrap(ErrInvalidIVSize, "длина IV CBC должна быть кратна размеру блока")
	}
	c := &CBC{
		block:     e.block,
		bulk:      e.bulk,
		fast:      e.cbc,
		blockSize: e.blockSize,
		padding:   padding,
	}
	if len(iv) == e.blockSize {
		copy(c.iv[:], iv)
	} else {
		c.ivHeap = append([]byte(nil), iv...)
		c.register = make([]byte, len(iv))
	}
	return c, nil
}

func (e engine) CFB(iv []byte) (*CFB, error) {
	return e.CFBN(iv, e.blockSize, e.blockSize)
}

func (e engine) CFBN(iv []byte, segmentSize, registerSize int) (*CFB, error) {
	if segmentSize == 0 {
		segmentSize = e.blockSize
	}
	if registerSize == 0 {
		registerSize = e.blockSize
	}
	if err := validateFeedback(e.blockSize, len(iv), segmentSize, registerSize); err != nil {
		return nil, err
	}
	fast := feedbackCipher(nil)
	bulk := blockBulkCipher(nil)
	if segmentSize == e.blockSize && registerSize == e.blockSize {
		fast = e.feedback
		bulk = e.bulk
	}
	cfb := &CFB{
		block:        e.block,
		bulk:         bulk,
		fast:         fast,
		blockSize:    e.blockSize,
		segmentSize:  segmentSize,
		registerSize: registerSize,
	}
	if registerSize > len(cfb.iv) {
		cfb.ivHeap = append([]byte(nil), iv...)
		cfb.registerHeap = make([]byte, registerSize)
	} else {
		copy(cfb.iv[:], iv)
	}
	return cfb, nil
}

func (e engine) OFB(iv []byte) (*OFB, error) {
	return e.OFBN(iv, e.blockSize, e.blockSize)
}

func (e engine) OFBN(iv []byte, segmentSize, registerSize int) (*OFB, error) {
	if segmentSize == 0 {
		segmentSize = e.blockSize
	}
	if registerSize == 0 {
		registerSize = e.blockSize
	}
	if err := validateFeedback(e.blockSize, len(iv), segmentSize, registerSize); err != nil {
		return nil, err
	}
	if registerSize%e.blockSize != 0 {
		return nil, errx.Wrap(ErrInvalidInput, "размер регистра OFB должен быть кратен размеру блока")
	}
	fast := feedbackCipher(nil)
	if segmentSize == e.blockSize && registerSize == e.blockSize {
		fast = e.feedback
	}
	ofb := &OFB{
		block:        e.block,
		fast:         fast,
		blockSize:    e.blockSize,
		segmentSize:  segmentSize,
		registerSize: registerSize,
	}
	if registerSize > len(ofb.iv) {
		ofb.ivHeap = append([]byte(nil), iv...)
		ofb.registerHeap = make([]byte, registerSize)
	} else {
		copy(ofb.iv[:], iv)
	}
	return ofb, nil
}

func (e engine) CTR(iv []byte) (*CTR, error) {
	if err := validateCTRIV(e.blockSize, len(iv)); err != nil {
		return nil, err
	}
	ctr := &CTR{
		block:       e.block,
		fast:        e.ctr,
		blockSize:   e.blockSize,
		segmentSize: e.blockSize,
	}
	copy(ctr.iv[:], iv)
	return ctr, nil
}

// CTRN is GOST R 34.13 CTR with a byte-granular segment s. The nonce is
// exactly half a block; each s-byte segment consumes one counter block.
func (e engine) CTRN(iv []byte, segmentSize int) (*CTR, error) {
	if len(iv) != e.blockSize/2 {
		return nil, ErrInvalidIVSize
	}
	if segmentSize < 1 || segmentSize > e.blockSize {
		return nil, ErrInvalidInput
	}
	c, err := e.CTR(iv)
	if err != nil {
		return nil, err
	}
	c.segmentSize = segmentSize
	return c, nil
}

func (e engine) CTRACPKM(iv []byte, sectionSize int) (*CTRACPKM, error) {
	if err := validateCTRIV(e.blockSize, len(iv)); err != nil {
		return nil, err
	}
	if sectionSize == 0 {
		sectionSize = DefaultACPKMSectionSize
	}
	if sectionSize <= 0 || sectionSize%e.blockSize != 0 {
		return nil, errx.Wrap(ErrInvalidInput, "некорректный размер секции CTR-ACPKM "+errx.Int(sectionSize))
	}
	c := &CTRACPKM{
		algorithm:   e.algorithm,
		key:         e.key,
		sbox:        e.sbox,
		blockSize:   e.blockSize,
		sectionSize: sectionSize,
		blocks:      []cipher.Block{e.block},
		fastBlocks:  []ctrCounterBlock{e.ctr},
	}
	copy(c.iv[:], iv)
	return c, nil
}

func (e engine) MAC(tagSize int) (*MAC, error) {
	return NewMAC(e.block, tagSize)
}

func newBlock(algorithm Algorithm, key []byte, sbox *gost28147.Sbox) (cipher.Block, error) {
	switch algorithm {
	case AlgorithmGOST28147:
		if len(key) != gost28147.KeySize {
			return nil, errx.Wrap(ErrInvalidKeySize, "длина ключа ГОСТ 28147-89 "+errx.Int(len(key)))
		}
		if sbox == nil {
			return nil, errx.Wrap(ErrInvalidInput, "nil S-box ГОСТ 28147-89")
		}
		return gost28147.NewCipher(key, sbox), nil
	case AlgorithmMagma:
		if len(key) != gost341264.KeySize {
			return nil, errx.Wrap(ErrInvalidKeySize, "длина ключа Магмы "+errx.Int(len(key)))
		}
		return gost341264.NewCipher(key), nil
	case AlgorithmKuznechik:
		if len(key) != gost3412128.KeySize {
			return nil, errx.Wrap(ErrInvalidKeySize, "длина ключа Кузнечика "+errx.Int(len(key)))
		}
		return gost3412128.NewCipher(key), nil
	default:
		return nil, ErrInvalidAlgorithm
	}
}

func validateBlockSize(blockSize int) error {
	if blockSize != gost341264.BlockSize && blockSize != gost3412128.BlockSize {
		return errx.Wrap(ErrInvalidBlockSize, errx.Int(blockSize))
	}
	return nil
}

func normalizeBlockPadding(p Padding) (Padding, error) {
	if p == PaddingDefault {
		return Padding2, nil
	}
	if err := validatePadding(p); err != nil {
		return PaddingDefault, err
	}
	return p, nil
}

func validateCTRIV(blockSize, n int) error {
	if n != blockSize/2 && n != blockSize {
		return errx.Wrap(ErrInvalidIVSize, errx.GotWantOr(n, blockSize/2, blockSize))
	}
	return nil
}

func validateFeedback(blockSize, ivSize, segmentSize, registerSize int) error {
	if segmentSize == 0 {
		segmentSize = blockSize
	}
	if registerSize == 0 {
		registerSize = blockSize
	}
	if segmentSize <= 0 || segmentSize > blockSize {
		return errx.Wrap(ErrInvalidInput, "некорректный размер сегмента "+errx.Int(segmentSize))
	}
	if registerSize < blockSize {
		return errx.Wrap(ErrInvalidInput, "некорректный размер регистра "+errx.Int(registerSize))
	}
	if ivSize != registerSize {
		return errx.Wrap(ErrInvalidIVSize, errx.GotWant(ivSize, registerSize))
	}
	return nil
}
