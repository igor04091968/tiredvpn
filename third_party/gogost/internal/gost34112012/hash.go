// GOST R 34.11-2012 hash function.
// RFC 6986.
package gost34112012

import (
	"encoding/binary"
	"math/bits"
)

const BlockSize = 64

type Hash struct {
	buf    [BlockSize]byte
	hsh    [BlockSize]byte
	chk    [BlockSize]byte
	n      uint64
	size   int
	bufLen int
}

// New creates a hash object with the requested digest size.
func New(size int) *Hash {
	h := NewValue(size)
	return &h
}

func NewValue(size int) Hash {
	if size != 32 && size != 64 {
		panic("gogost/internal/gost34112012: размер должен быть 32 или 64")
	}
	h := Hash{size: size}
	h.Reset()
	return h
}

func (h *Hash) Reset() {
	h.n = 0
	h.bufLen = 0
	clear(h.chk[:])
	for i := range BlockSize {
		if h.size == 32 {
			h.hsh[i] = 1
		} else {
			h.hsh[i] = 0
		}
	}
}

func (h *Hash) BlockSize() int {
	return BlockSize
}

func (h *Hash) Size() int {
	return h.size
}

func add512bit(out, chk, data []byte) []byte {
	var carry uint64
	for i := range 8 {
		lo := i * 8
		sum, c := bits.Add64(
			binary.LittleEndian.Uint64(chk[lo:lo+8]),
			binary.LittleEndian.Uint64(data[lo:lo+8]),
			carry,
		)
		binary.LittleEndian.PutUint64(out[lo:lo+8], sum)
		carry = c
	}
	return out
}

func loadWords(dst *[8]uint64, src []byte) {
	_ = src[63]
	for i := range 8 {
		lo := i * 8
		dst[i] = binary.LittleEndian.Uint64(src[lo : lo+8])
	}
}

func storeWords(dst []byte, src *[8]uint64) {
	_ = dst[63]
	for i := range 8 {
		lo := i * 8
		binary.LittleEndian.PutUint64(dst[lo:lo+8], src[i])
	}
}

func lpsWords(out, data *[8]uint64) {
	w0, w1, w2, w3 := data[0], data[1], data[2], data[3]
	w4, w5, w6, w7 := data[4], data[5], data[6], data[7]
	out[0] = precalc[0][byte(w0)] ^
		precalc[1][byte(w1)] ^
		precalc[2][byte(w2)] ^
		precalc[3][byte(w3)] ^
		precalc[4][byte(w4)] ^
		precalc[5][byte(w5)] ^
		precalc[6][byte(w6)] ^
		precalc[7][byte(w7)]
	out[1] = precalc[0][byte(w0>>8)] ^
		precalc[1][byte(w1>>8)] ^
		precalc[2][byte(w2>>8)] ^
		precalc[3][byte(w3>>8)] ^
		precalc[4][byte(w4>>8)] ^
		precalc[5][byte(w5>>8)] ^
		precalc[6][byte(w6>>8)] ^
		precalc[7][byte(w7>>8)]
	out[2] = precalc[0][byte(w0>>16)] ^
		precalc[1][byte(w1>>16)] ^
		precalc[2][byte(w2>>16)] ^
		precalc[3][byte(w3>>16)] ^
		precalc[4][byte(w4>>16)] ^
		precalc[5][byte(w5>>16)] ^
		precalc[6][byte(w6>>16)] ^
		precalc[7][byte(w7>>16)]
	out[3] = precalc[0][byte(w0>>24)] ^
		precalc[1][byte(w1>>24)] ^
		precalc[2][byte(w2>>24)] ^
		precalc[3][byte(w3>>24)] ^
		precalc[4][byte(w4>>24)] ^
		precalc[5][byte(w5>>24)] ^
		precalc[6][byte(w6>>24)] ^
		precalc[7][byte(w7>>24)]
	out[4] = precalc[0][byte(w0>>32)] ^
		precalc[1][byte(w1>>32)] ^
		precalc[2][byte(w2>>32)] ^
		precalc[3][byte(w3>>32)] ^
		precalc[4][byte(w4>>32)] ^
		precalc[5][byte(w5>>32)] ^
		precalc[6][byte(w6>>32)] ^
		precalc[7][byte(w7>>32)]
	out[5] = precalc[0][byte(w0>>40)] ^
		precalc[1][byte(w1>>40)] ^
		precalc[2][byte(w2>>40)] ^
		precalc[3][byte(w3>>40)] ^
		precalc[4][byte(w4>>40)] ^
		precalc[5][byte(w5>>40)] ^
		precalc[6][byte(w6>>40)] ^
		precalc[7][byte(w7>>40)]
	out[6] = precalc[0][byte(w0>>48)] ^
		precalc[1][byte(w1>>48)] ^
		precalc[2][byte(w2>>48)] ^
		precalc[3][byte(w3>>48)] ^
		precalc[4][byte(w4>>48)] ^
		precalc[5][byte(w5>>48)] ^
		precalc[6][byte(w6>>48)] ^
		precalc[7][byte(w7>>48)]
	out[7] = precalc[0][byte(w0>>56)] ^
		precalc[1][byte(w1>>56)] ^
		precalc[2][byte(w2>>56)] ^
		precalc[3][byte(w3>>56)] ^
		precalc[4][byte(w4>>56)] ^
		precalc[5][byte(w5>>56)] ^
		precalc[6][byte(w6>>56)] ^
		precalc[7][byte(w7>>56)]
}

var cWords = func() [12][8]uint64 {
	var words [12][8]uint64
	for i := range c {
		loadWords(&words[i], c[i][:])
	}
	return words
}()

func eWords(out, k, msg *[8]uint64) {
	m := *msg
	kk := *k
	var x [8]uint64
	for i := range 12 {
		for j := range 8 {
			x[j] = kk[j] ^ m[j]
		}
		lpsWords(&m, &x)
		for j := range 8 {
			x[j] = kk[j] ^ cWords[i][j]
		}
		lpsWords(&kk, &x)
	}
	for i := range 8 {
		out[i] = kk[i] ^ m[i]
	}
}

func (h *Hash) g(dst []byte, n uint64, hsh, data []byte) {
	var hWords, dataWords, keyWords, out [8]uint64
	loadWords(&hWords, hsh)
	loadWords(&dataWords, data)
	keyWords = hWords
	keyWords[0] ^= n
	lpsWords(&keyWords, &keyWords)
	eWords(&out, &keyWords, &dataWords)
	for i := range 8 {
		out[i] ^= hWords[i] ^ dataWords[i]
	}
	storeWords(dst, &out)
}

func (h *Hash) Write(data []byte) (int, error) {
	nn := len(data)
	if h.bufLen > 0 {
		n := copy(h.buf[h.bufLen:], data)
		h.bufLen += n
		data = data[n:]
		if h.bufLen < BlockSize {
			return nn, nil
		}
		h.g(h.hsh[:], h.n, h.hsh[:], h.buf[:])
		add512bit(h.chk[:], h.chk[:], h.buf[:])
		h.n += BlockSize * 8
		h.bufLen = 0
	}
	for len(data) >= BlockSize {
		block := data[:BlockSize]
		h.g(h.hsh[:], h.n, h.hsh[:], block)
		add512bit(h.chk[:], h.chk[:], block)
		h.n += BlockSize * 8
		data = data[BlockSize:]
	}
	if len(data) > 0 {
		h.bufLen = copy(h.buf[:], data)
	}
	return nn, nil
}

func (h *Hash) checkSum() [BlockSize]byte {
	var buf, hsh, tmp, addBuf [BlockSize]byte
	copy(buf[:], h.buf[:h.bufLen])
	buf[h.bufLen] = 1
	h.g(hsh[:], h.n, h.hsh[:], buf[:])
	binary.LittleEndian.PutUint64(tmp[:], h.n+uint64(h.bufLen)*8)
	h.g(hsh[:], 0, hsh[:], tmp[:])
	h.g(hsh[:], 0, hsh[:], add512bit(addBuf[:], h.chk[:], buf[:]))
	return hsh
}

func (h *Hash) Sum(in []byte) []byte {
	hsh := h.checkSum()
	if h.size == 32 {
		return append(in, hsh[BlockSize/2:]...)
	}
	return append(in, hsh[:]...)
}

// Sum256Into writes the 256-bit digest without converting through hash.Hash
// or appending to a caller-owned slice. The receiver is not mutated.
func (h *Hash) Sum256Into(out *[32]byte) {
	if h.size != 32 {
		panic("gogost/internal/gost34112012: Sum256Into requires a 256-bit hash")
	}
	hsh := h.checkSum()
	copy(out[:], hsh[BlockSize/2:])
}

func Sum256(data []byte) [32]byte {
	var h Hash
	h.size = 32
	h.Reset()
	_, _ = h.Write(data)
	hsh := h.checkSum()
	var out [32]byte
	copy(out[:], hsh[BlockSize/2:])
	return out
}

func Sum512(data []byte) [64]byte {
	var h Hash
	h.size = 64
	h.Reset()
	_, _ = h.Write(data)
	return h.checkSum()
}
