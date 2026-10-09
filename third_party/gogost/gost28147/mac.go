package gost28147

import (
	"errors"

	"gitverse.ru/uzer_007/gogost/v3/internal/errx"
)

var SeqMAC = Seq([]uint8{
	0, 1, 2, 3, 4, 5, 6, 7,
	0, 1, 2, 3, 4, 5, 6, 7,
})

type MAC struct {
	c    *Cipher
	size int

	rem    [BlockSize]byte
	remLen int

	ivN1, ivN2 nv
	n1, n2     nv
}

// NewMAC создаёт MAC с заданным размером тега и начальным вектором.
func (c *Cipher) NewMAC(size int, iv []byte) (*MAC, error) {
	m, err := c.NewMACValue(size, iv)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func (c *Cipher) NewMACValue(size int, iv []byte) (MAC, error) {
	if size == 0 || size > 8 {
		return MAC{}, errors.New("gogost/gost28147: Некорректный размер тега (0<" + errx.Int(size) + "<=8)")
	}
	if len(iv) != BlockSize {
		return MAC{}, errors.New("gogost/gost28147: длина IV " + errx.Int(len(iv)) + ", ожидалось " + errx.Int(BlockSize))
	}
	m := MAC{c: c, size: size}
	m.ivN1, m.ivN2 = block2nvs(iv)
	m.Reset()
	return m, nil
}

func (c *Cipher) SumMAC(dst, data []byte, size int, iv []byte) ([]byte, error) {
	if size == 0 || size > 8 {
		return nil, errors.New("gogost/gost28147: Некорректный размер тега (0<" + errx.Int(size) + "<=8)")
	}
	if len(iv) != BlockSize {
		return nil, errors.New("gogost/gost28147: длина IV " + errx.Int(len(iv)) + ", ожидалось " + errx.Int(BlockSize))
	}
	n1, n2 := block2nvs(iv)
	keys := &c.macKeys
	table := c.table
	for len(data) >= BlockSize {
		r1, r2 := block2nvs(data)
		n1, n2 = xcrypt16(keys, table, n1^r1, n2^r2)
		data = data[BlockSize:]
	}
	if len(data) > 0 {
		var block [BlockSize]byte
		copy(block[:], data)
		r1, r2 := block2nvs(block[:])
		n1, n2 = xcrypt16(keys, table, n1^r1, n2^r2)
	}

	var out [BlockSize]byte
	store32LE(out[0:4], uint32(n1))
	store32LE(out[4:8], uint32(n2))
	return append(dst, out[:size]...), nil
}

func (m *MAC) Reset() {
	m.n1 = m.ivN1
	m.n2 = m.ivN2
	m.remLen = 0
}

func (m *MAC) BlockSize() int {
	return BlockSize
}

func (m *MAC) Size() int {
	return m.size
}

func (m *MAC) processBlock(block []byte) {
	n1, n2 := block2nvs(block)
	m.n1, m.n2 = xcrypt16(&m.c.macKeys, m.c.table, m.n1^n1, m.n2^n2)
}

func (m *MAC) Write(b []byte) (int, error) {
	n0 := len(b)

	if m.remLen > 0 {
		k := copy(m.rem[m.remLen:], b)
		m.remLen += k
		b = b[k:]
		if m.remLen < BlockSize {
			return n0, nil
		}
		m.processBlock(m.rem[:])
		m.remLen = 0
	}

	n1, n2 := m.n1, m.n2
	keys := &m.c.macKeys
	table := m.c.table
	for len(b) >= BlockSize {
		r1, r2 := block2nvs(b)
		n1, n2 = xcrypt16(keys, table, n1^r1, n2^r2)
		b = b[BlockSize:]
	}
	m.n1, m.n2 = n1, n2

	if len(b) > 0 {
		m.remLen = copy(m.rem[:], b)
	}
	return n0, nil
}

func (m *MAC) Sum(b []byte) []byte {
	n1, n2 := m.n1, m.n2
	if m.remLen > 0 {
		var block [BlockSize]byte
		copy(block[:], m.rem[:m.remLen])
		r1, r2 := block2nvs(block[:])
		n1, n2 = xcrypt16(&m.c.macKeys, m.c.table, n1^r1, n2^r2)
	}

	var out [BlockSize]byte
	store32LE(out[0:4], uint32(n1))
	store32LE(out[4:8], uint32(n2))
	return append(b, out[:m.size]...)
}
