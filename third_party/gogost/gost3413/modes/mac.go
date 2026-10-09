package modes

import (
	"crypto/cipher"
	"crypto/hmac"

	"gitverse.ru/uzer_007/gogost/v3/internal/errx"
)

// MAC представляет подготовленный код аутентификации ГОСТ Р 34.13, близкий к CMAC.
type MAC struct {
	block     cipher.Block
	fast      macCipher
	blockSize int
	tagSize   int
	k1        [16]byte
	k2        [16]byte
	last      []byte
	padded    []byte
	state     []byte
	tag       []byte
}

type macCipher interface {
	SumGOST3413MAC(dst, data []byte, tagSize int) []byte
	VerifyGOST3413MAC(data, tag []byte) bool
}

// NewMAC создаёт подготовленный MAC-объект для существующего блочного шифра.
func NewMAC(block cipher.Block, tagSize int) (*MAC, error) {
	if block == nil {
		return nil, ErrInvalidBlockSize
	}
	blockSize := block.BlockSize()
	if err := validateBlockSize(blockSize); err != nil {
		return nil, err
	}
	if tagSize == 0 {
		tagSize = blockSize
	}
	if tagSize <= 0 || tagSize > blockSize {
		return nil, errx.Wrap(ErrInvalidTagSize, errx.Int(tagSize))
	}
	fast, _ := block.(macCipher)
	m := &MAC{
		block:     block,
		fast:      fast,
		blockSize: blockSize,
		tagSize:   tagSize,
	}
	if fast != nil {
		return m, nil
	}
	m.last = make([]byte, blockSize)
	m.padded = make([]byte, blockSize)
	m.state = make([]byte, blockSize)
	m.tag = make([]byte, tagSize)
	var zero, l [16]byte
	block.Encrypt(l[:blockSize], zero[:blockSize])
	doubleSubkeyInto(m.k1[:blockSize], l[:blockSize])
	doubleSubkeyInto(m.k2[:blockSize], m.k1[:blockSize])
	return m, nil
}

func (m *MAC) Sum(dst, data []byte) []byte {
	if m.fast != nil {
		return m.fast.SumGOST3413MAC(dst, data, m.tagSize)
	}
	ret, out := sliceForAppend(dst, m.tagSize)
	m.macInto(out, data)
	return ret
}

func (m *MAC) Verify(data, tag []byte) bool {
	if len(tag) != m.tagSize {
		return false
	}
	if m.fast != nil {
		return m.fast.VerifyGOST3413MAC(data, tag)
	}
	m.macInto(m.tag, data)
	return hmac.Equal(m.tag, tag)
}

func (m *MAC) macInto(out, data []byte) {
	var fullBlocks int
	clear(m.last)
	clear(m.padded)
	clear(m.state)
	if len(data) > 0 && len(data)%m.blockSize == 0 {
		fullBlocks = len(data)/m.blockSize - 1
		xorInto(m.last, data[len(data)-m.blockSize:], m.k1[:m.blockSize])
	} else {
		fullBlocks = len(data) / m.blockSize
		copy(m.padded, data[fullBlocks*m.blockSize:])
		m.padded[len(data)-fullBlocks*m.blockSize] = 0x80
		xorInto(m.last, m.padded, m.k2[:m.blockSize])
	}

	for i := 0; i < fullBlocks; i++ {
		xorInto(m.state, m.state, data[i*m.blockSize:(i+1)*m.blockSize])
		m.block.Encrypt(m.state, m.state)
	}
	xorInto(m.state, m.state, m.last)
	m.block.Encrypt(m.state, m.state)
	copy(out, m.state[:m.tagSize])
}

func doubleSubkeyInto(out, k []byte) {
	var carry byte
	for i := len(k) - 1; i >= 0; i-- {
		nextCarry := k[i] >> 7
		out[i] = (k[i] << 1) | carry
		carry = nextCarry
	}
	if carry != 0 {
		switch len(k) {
		case 8:
			out[len(out)-1] ^= 0x1b
		case 16:
			out[len(out)-1] ^= 0x87
		}
	}
}
