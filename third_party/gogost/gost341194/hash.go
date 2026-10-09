// Package gost341194 реализует хеш-функцию ГОСТ Р 34.11-94 по RFC 5831.
package gost341194

import (
	"encoding/binary"

	"gitverse.ru/uzer_007/gogost/v3/gost28147"
)

const (
	BlockSize = 32
	Size      = 32
)

var (
	SboxDefault *gost28147.Sbox = &gost28147.SboxIdGostR341194TestParamSet

	c2 [BlockSize]byte = [BlockSize]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	c3 [BlockSize]byte = [BlockSize]byte{
		0xff, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0xff,
		0xff, 0x00, 0x00, 0xff, 0x00, 0xff, 0xff, 0x00,
		0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff,
		0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00,
	}
	c4 [BlockSize]byte = [BlockSize]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
)

type Hash struct {
	sbox   *gost28147.Sbox
	table  *[4][256]uint32
	custom *[4][256]uint32
	chk    [BlockSize]byte
	buf    [BlockSize]byte
	hsh    [BlockSize]byte
	tmp    [BlockSize]byte
	size   uint64
	off    int
}

func New(sbox *gost28147.Sbox) *Hash {
	h := Hash{sbox: sbox}
	h.initTable(sbox)
	h.Reset()
	return &h
}

func (h *Hash) Reset() {
	h.size = 0
	clear(h.hsh[:])
	clear(h.chk[:])
	h.off = 0
}

func (h *Hash) BlockSize() int {
	return BlockSize
}

func (h *Hash) Size() int {
	return BlockSize
}

func fAInto(out, in *[BlockSize]byte) {
	out[0] = in[16+0] ^ in[24+0]
	out[1] = in[16+1] ^ in[24+1]
	out[2] = in[16+2] ^ in[24+2]
	out[3] = in[16+3] ^ in[24+3]
	out[4] = in[16+4] ^ in[24+4]
	out[5] = in[16+5] ^ in[24+5]
	out[6] = in[16+6] ^ in[24+6]
	out[7] = in[16+7] ^ in[24+7]
	copy(out[8:], in[0:24])
}

func fPReverseInto(out, in *[BlockSize]byte) {
	*out = [BlockSize]byte{
		in[31], in[23], in[15], in[7], in[30], in[22], in[14], in[6],
		in[29], in[21], in[13], in[5], in[28], in[20], in[12], in[4],
		in[27], in[19], in[11], in[3], in[26], in[18], in[10], in[2],
		in[25], in[17], in[9], in[1], in[24], in[16], in[8], in[0],
	}
}

func fChiApply(inout *[BlockSize]byte) {
	w0 := binary.LittleEndian.Uint16(inout[0:2])
	w1 := binary.LittleEndian.Uint16(inout[2:4])
	w2 := binary.LittleEndian.Uint16(inout[4:6])
	w3 := binary.LittleEndian.Uint16(inout[6:8])
	w4 := binary.LittleEndian.Uint16(inout[8:10])
	w5 := binary.LittleEndian.Uint16(inout[10:12])
	w6 := binary.LittleEndian.Uint16(inout[12:14])
	w7 := binary.LittleEndian.Uint16(inout[14:16])
	w8 := binary.LittleEndian.Uint16(inout[16:18])
	w9 := binary.LittleEndian.Uint16(inout[18:20])
	w10 := binary.LittleEndian.Uint16(inout[20:22])
	w11 := binary.LittleEndian.Uint16(inout[22:24])
	w12 := binary.LittleEndian.Uint16(inout[24:26])
	w13 := binary.LittleEndian.Uint16(inout[26:28])
	w14 := binary.LittleEndian.Uint16(inout[28:30])
	w15 := binary.LittleEndian.Uint16(inout[30:32])

	binary.LittleEndian.PutUint16(inout[0:2], w15^w14^w13^w12^w0^w3)
	binary.LittleEndian.PutUint16(inout[2:4], w0)
	binary.LittleEndian.PutUint16(inout[4:6], w1)
	binary.LittleEndian.PutUint16(inout[6:8], w2)
	binary.LittleEndian.PutUint16(inout[8:10], w3)
	binary.LittleEndian.PutUint16(inout[10:12], w4)
	binary.LittleEndian.PutUint16(inout[12:14], w5)
	binary.LittleEndian.PutUint16(inout[14:16], w6)
	binary.LittleEndian.PutUint16(inout[16:18], w7)
	binary.LittleEndian.PutUint16(inout[18:20], w8)
	binary.LittleEndian.PutUint16(inout[20:22], w9)
	binary.LittleEndian.PutUint16(inout[22:24], w10)
	binary.LittleEndian.PutUint16(inout[24:26], w11)
	binary.LittleEndian.PutUint16(inout[26:28], w12)
	binary.LittleEndian.PutUint16(inout[28:30], w13)
	binary.LittleEndian.PutUint16(inout[30:32], w14)
}

func blockReverse(dst, src []byte) {
	for i, j := 0, BlockSize-1; i < j; i, j = i+1, j-1 {
		dst[i], dst[j] = src[j], src[i]
	}
}

func blockXor(dst, a, b *[BlockSize]byte) {
	for i := range BlockSize {
		dst[i] = a[i] ^ b[i]
	}
}

var (
	gost28147TableR341194Test      = makeGOST28147Table(&gost28147.SboxIdGostR341194TestParamSet)
	gost28147TableR341194CryptoPro = makeGOST28147Table(&gost28147.SboxIdGostR341194CryptoProParamSet)
)

func (h *Hash) initTable(sbox *gost28147.Sbox) {
	switch sbox {
	case &gost28147.SboxIdGostR341194TestParamSet:
		h.table = &gost28147TableR341194Test
	case &gost28147.SboxIdGostR341194CryptoProParamSet:
		h.table = &gost28147TableR341194CryptoPro
	default:
		table := makeGOST28147Table(sbox)
		h.custom = &table
		h.table = h.custom
	}
}

func makeGOST28147Table(sbox *gost28147.Sbox) [4][256]uint32 {
	var table [4][256]uint32
	for pos := range 4 {
		lo := sbox[pos*2]
		hi := sbox[pos*2+1]
		shift := uint(pos * 8)
		for b := range 256 {
			v := uint32(lo[b&0x0f])<<shift | uint32(hi[b>>4])<<(shift+4)
			table[pos][b] = v<<11 | v>>(32-11)
		}
	}
	return table
}

func gost28147Lookup(table *[4][256]uint32, n uint32) uint32 {
	return table[0][byte(n)] ^
		table[1][byte(n>>8)] ^
		table[2][byte(n>>16)] ^
		table[3][byte(n>>24)]
}

func encryptGOST28147Words(key *[BlockSize]byte, table *[4][256]uint32, n1, n2 uint32) (uint32, uint32) {
	k0 := binary.LittleEndian.Uint32(key[0:4])
	k1 := binary.LittleEndian.Uint32(key[4:8])
	k2 := binary.LittleEndian.Uint32(key[8:12])
	k3 := binary.LittleEndian.Uint32(key[12:16])
	k4 := binary.LittleEndian.Uint32(key[16:20])
	k5 := binary.LittleEndian.Uint32(key[20:24])
	k6 := binary.LittleEndian.Uint32(key[24:28])
	k7 := binary.LittleEndian.Uint32(key[28:32])

	n1, n2 = gost28147Lookup(table, n1+k0)^n2, n1
	n1, n2 = gost28147Lookup(table, n1+k1)^n2, n1
	n1, n2 = gost28147Lookup(table, n1+k2)^n2, n1
	n1, n2 = gost28147Lookup(table, n1+k3)^n2, n1
	n1, n2 = gost28147Lookup(table, n1+k4)^n2, n1
	n1, n2 = gost28147Lookup(table, n1+k5)^n2, n1
	n1, n2 = gost28147Lookup(table, n1+k6)^n2, n1
	n1, n2 = gost28147Lookup(table, n1+k7)^n2, n1
	n1, n2 = gost28147Lookup(table, n1+k0)^n2, n1
	n1, n2 = gost28147Lookup(table, n1+k1)^n2, n1
	n1, n2 = gost28147Lookup(table, n1+k2)^n2, n1
	n1, n2 = gost28147Lookup(table, n1+k3)^n2, n1
	n1, n2 = gost28147Lookup(table, n1+k4)^n2, n1
	n1, n2 = gost28147Lookup(table, n1+k5)^n2, n1
	n1, n2 = gost28147Lookup(table, n1+k6)^n2, n1
	n1, n2 = gost28147Lookup(table, n1+k7)^n2, n1
	n1, n2 = gost28147Lookup(table, n1+k0)^n2, n1
	n1, n2 = gost28147Lookup(table, n1+k1)^n2, n1
	n1, n2 = gost28147Lookup(table, n1+k2)^n2, n1
	n1, n2 = gost28147Lookup(table, n1+k3)^n2, n1
	n1, n2 = gost28147Lookup(table, n1+k4)^n2, n1
	n1, n2 = gost28147Lookup(table, n1+k5)^n2, n1
	n1, n2 = gost28147Lookup(table, n1+k6)^n2, n1
	n1, n2 = gost28147Lookup(table, n1+k7)^n2, n1
	n1, n2 = gost28147Lookup(table, n1+k7)^n2, n1
	n1, n2 = gost28147Lookup(table, n1+k6)^n2, n1
	n1, n2 = gost28147Lookup(table, n1+k5)^n2, n1
	n1, n2 = gost28147Lookup(table, n1+k4)^n2, n1
	n1, n2 = gost28147Lookup(table, n1+k3)^n2, n1
	n1, n2 = gost28147Lookup(table, n1+k2)^n2, n1
	n1, n2 = gost28147Lookup(table, n1+k1)^n2, n1
	n1, n2 = gost28147Lookup(table, n1+k0)^n2, n1

	return n1, n2
}

func (h *Hash) stepInto(dst, hin, m *[BlockSize]byte) {
	var out, u, v, tmp [BlockSize]byte
	hinCopy := *hin
	u = hinCopy
	v = *m
	h.stepEncryptPart(&out, &u, &v, &hinCopy, 24)
	fAInto(&tmp, &u)
	blockXor(&u, &tmp, &c2)
	fAInto(&tmp, &v)
	fAInto(&v, &tmp)
	h.stepEncryptPart(&out, &u, &v, &hinCopy, 16)
	fAInto(&tmp, &u)
	blockXor(&u, &tmp, &c3)
	fAInto(&tmp, &v)
	fAInto(&v, &tmp)
	h.stepEncryptPart(&out, &u, &v, &hinCopy, 8)
	fAInto(&tmp, &u)
	blockXor(&u, &tmp, &c4)
	fAInto(&tmp, &v)
	fAInto(&v, &tmp)
	h.stepEncryptPart(&out, &u, &v, &hinCopy, 0)
	for i := 0; i < 12; i++ {
		fChiApply(&out)
	}
	blockXor(&out, &out, m)
	fChiApply(&out)
	blockXor(&out, &out, &hinCopy)
	for i := 0; i < 61; i++ {
		fChiApply(&out)
	}
	*dst = out
}

func (h *Hash) stepEncryptPart(out, u, v, hin *[BlockSize]byte, offset int) {
	var k, key [BlockSize]byte
	blockXor(&k, u, v)
	fPReverseInto(&key, &k)
	n1 := binary.BigEndian.Uint32(hin[offset+4 : offset+8])
	n2 := binary.BigEndian.Uint32(hin[offset : offset+4])
	n1, n2 = encryptGOST28147Words(&key, h.table, n1, n2)
	binary.BigEndian.PutUint32(out[offset:offset+4], n1)
	binary.BigEndian.PutUint32(out[offset+4:offset+8], n2)
}

func add256(dst, a, b []byte) {
	var carry uint16
	for i := BlockSize - 1; i >= 0; i-- {
		sum := uint16(a[i]) + uint16(b[i]) + carry
		dst[i] = byte(sum)
		carry = sum >> 8
	}
}

func (h *Hash) Write(data []byte) (int, error) {
	nn := len(data)
	if h.off > 0 {
		n := copy(h.buf[h.off:], data)
		h.off += n
		data = data[n:]
		if h.off < BlockSize {
			return nn, nil
		}
		h.size += BlockSize * 8
		blockReverse(h.tmp[:], h.buf[:])
		add256(h.chk[:], h.chk[:], h.tmp[:])
		h.stepInto(&h.hsh, &h.hsh, &h.tmp)
		h.off = 0
	}
	for len(data) >= BlockSize {
		h.size += BlockSize * 8
		blockReverse(h.tmp[:], data[:BlockSize])
		add256(h.chk[:], h.chk[:], h.tmp[:])
		h.stepInto(&h.hsh, &h.hsh, &h.tmp)
		data = data[BlockSize:]
	}
	if len(data) > 0 {
		h.off = copy(h.buf[:], data)
	}
	return nn, nil
}

func (h *Hash) Sum(in []byte) []byte {
	size := h.size
	chk := h.chk
	hsh := h.hsh
	var block [BlockSize]byte
	if h.off != 0 {
		size += uint64(h.off) * 8
		copy(block[:], h.buf[:h.off])
		blockReverse(block[:], block[:])
		add256(chk[:], chk[:], block[:])
		h.stepInto(&hsh, &hsh, &block)
		clear(block[:])
	}
	binary.BigEndian.PutUint64(block[24:], size)
	h.stepInto(&hsh, &hsh, &block)
	h.stepInto(&hsh, &hsh, &chk)
	blockReverse(hsh[:], hsh[:])
	return append(in, hsh[:]...)
}

func Sum(data []byte, sbox *gost28147.Sbox) [Size]byte {
	var h Hash
	h.sbox = sbox
	h.initTable(sbox)
	h.Reset()
	_, _ = h.Write(data)
	var out [Size]byte
	h.Sum(out[:0])
	return out
}
