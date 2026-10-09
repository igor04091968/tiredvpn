// Copyright 2012-2020 The Go Authors. All rights reserved.
// Copyright 2024 Solar Designer. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package yescrypt contains the fixed-parameter yescrypt core used by
// GOST yescrypt. It is derived from github.com/go-crypt/x/yescrypt.
package yescrypt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/bits"
	"unsafe"

	"github.com/go-crypt/x/pbkdf2"
)

const (
	N = 32768
	r = 8
)

func blockCopy(dst, src []uint64, n int) {
	copy(dst, src[:n])
}

func blockXOR(dst, src []uint64, n int) {
	xorWords(dst, src, n)
}

func salsaXOR(tmp *[8]uint64, in, out []uint64, rounds int) {
	d0 := tmp[0] ^ in[0]
	d1 := tmp[1] ^ in[1]
	d2 := tmp[2] ^ in[2]
	d3 := tmp[3] ^ in[3]
	d4 := tmp[4] ^ in[4]
	d5 := tmp[5] ^ in[5]
	d6 := tmp[6] ^ in[6]
	d7 := tmp[7] ^ in[7]

	x0, x1 := uint32(d0), uint32(d6>>32)
	x2, x3 := uint32(d5), uint32(d3>>32)
	x4, x5 := uint32(d2), uint32(d0>>32)
	x6, x7 := uint32(d7), uint32(d5>>32)
	x8, x9 := uint32(d4), uint32(d2>>32)
	x10, x11 := uint32(d1), uint32(d7>>32)
	x12, x13 := uint32(d6), uint32(d4>>32)
	x14, x15 := uint32(d3), uint32(d1>>32)

	for i := 0; i < rounds; i += 2 {
		x4 ^= bits.RotateLeft32(x0+x12, 7)
		x8 ^= bits.RotateLeft32(x4+x0, 9)
		x12 ^= bits.RotateLeft32(x8+x4, 13)
		x0 ^= bits.RotateLeft32(x12+x8, 18)

		x9 ^= bits.RotateLeft32(x5+x1, 7)
		x13 ^= bits.RotateLeft32(x9+x5, 9)
		x1 ^= bits.RotateLeft32(x13+x9, 13)
		x5 ^= bits.RotateLeft32(x1+x13, 18)

		x14 ^= bits.RotateLeft32(x10+x6, 7)
		x2 ^= bits.RotateLeft32(x14+x10, 9)
		x6 ^= bits.RotateLeft32(x2+x14, 13)
		x10 ^= bits.RotateLeft32(x6+x2, 18)

		x3 ^= bits.RotateLeft32(x15+x11, 7)
		x7 ^= bits.RotateLeft32(x3+x15, 9)
		x11 ^= bits.RotateLeft32(x7+x3, 13)
		x15 ^= bits.RotateLeft32(x11+x7, 18)

		x1 ^= bits.RotateLeft32(x0+x3, 7)
		x2 ^= bits.RotateLeft32(x1+x0, 9)
		x3 ^= bits.RotateLeft32(x2+x1, 13)
		x0 ^= bits.RotateLeft32(x3+x2, 18)

		x6 ^= bits.RotateLeft32(x5+x4, 7)
		x7 ^= bits.RotateLeft32(x6+x5, 9)
		x4 ^= bits.RotateLeft32(x7+x6, 13)
		x5 ^= bits.RotateLeft32(x4+x7, 18)

		x11 ^= bits.RotateLeft32(x10+x9, 7)
		x8 ^= bits.RotateLeft32(x11+x10, 9)
		x9 ^= bits.RotateLeft32(x8+x11, 13)
		x10 ^= bits.RotateLeft32(x9+x8, 18)

		x12 ^= bits.RotateLeft32(x15+x14, 7)
		x13 ^= bits.RotateLeft32(x12+x15, 9)
		x14 ^= bits.RotateLeft32(x13+x12, 13)
		x15 ^= bits.RotateLeft32(x14+x13, 18)
	}

	d0 = uint64(uint32(d0)+x0) | uint64(uint32(d0>>32)+x5)<<32
	d1 = uint64(uint32(d1)+x10) | uint64(uint32(d1>>32)+x15)<<32
	d2 = uint64(uint32(d2)+x4) | uint64(uint32(d2>>32)+x9)<<32
	d3 = uint64(uint32(d3)+x14) | uint64(uint32(d3>>32)+x3)<<32
	d4 = uint64(uint32(d4)+x8) | uint64(uint32(d4>>32)+x13)<<32
	d5 = uint64(uint32(d5)+x2) | uint64(uint32(d5>>32)+x7)<<32
	d6 = uint64(uint32(d6)+x12) | uint64(uint32(d6>>32)+x1)<<32
	d7 = uint64(uint32(d7)+x6) | uint64(uint32(d7>>32)+x11)<<32

	out[0], tmp[0] = d0, d0
	out[1], tmp[1] = d1, d1
	out[2], tmp[2] = d2, d2
	out[3], tmp[3] = d3, d3
	out[4], tmp[4] = d4, d4
	out[5], tmp[5] = d5, d5
	out[6], tmp[6] = d6, d6
	out[7], tmp[7] = d7, d7
}

func blockMix(tmp *[8]uint64, in, out []uint64, r int) {
	blockCopy(tmp[:], in[(2*r-1)*8:], 8)
	for i := 0; i < 2*r; i += 2 {
		salsaXOR(tmp, in[i*8:], out[i*4:], 8)
		salsaXOR(tmp, in[i*8+8:], out[i*4+r*8:], 8)
	}
}

const (
	pwxSimple = 2
	pwxGather = 4
	pwxRounds = 6
	sWidth    = 8
	pwxBytes  = pwxGather * pwxSimple * 8
	pwxWords  = pwxBytes / 8
	sWords    = 3 * (1 << sWidth) * pwxSimple
	sMask     = ((1 << sWidth) - 1) * pwxSimple * 8
	sTableLen = (1 << sWidth) * pwxSimple
)

type sTable [sTableLen]uint64

type pwxformCtx struct {
	s0, s1, s2 *sTable
	w          uint32
}

// tableLoad/tableStore omit redundant bounds checks. Every caller masks the
// index with sMask (or sTableLen-1 for w), so index and index+1 are in range.
func tableLoad(table *sTable, index uint32) uint64 {
	return *(*uint64)(unsafe.Add(unsafe.Pointer(table), uintptr(index)*8))
}

func tableStore(table *sTable, index uint32, value uint64) {
	*(*uint64)(unsafe.Add(unsafe.Pointer(table), uintptr(index)*8)) = value
}

func pwxformGeneric(x *[pwxWords]uint64, ctx *pwxformCtx) {
	s0, s1, s2, w := ctx.s0, ctx.s1, ctx.s2, ctx.w

	for i := 0; i < pwxRounds; i++ {
		for j := 0; j < pwxGather; j++ {
			pos := j * pwxSimple
			word := x[pos]
			xl := uint32(word)
			xh := uint32(word >> 32)
			word = uint64(xh) * uint64(xl)
			xl = (xl & sMask) / 8
			xh = (xh & sMask) / 8
			word = (word + tableLoad(s0, xl)) ^ tableLoad(s1, xh)
			x[pos] = word
			y := x[pos+1]
			y = ((y>>32)*uint64(uint32(y)) + tableLoad(s0, xl+1)) ^ tableLoad(s1, xh+1)
			x[pos+1] = y
			if i != 0 && i != pwxRounds-1 {
				tableStore(s2, w, word)
				tableStore(s2, w+1, y)
				w += 2
			}
		}
	}

	ctx.s0, ctx.s1, ctx.s2 = s2, s0, s1
	ctx.w = w & (sTableLen - 1)
}

func blockMixPwxform(x *[pwxWords]uint64, b []uint64, ctx *pwxformCtx) {
	const r1 = 128 * r / pwxBytes
	blockCopy(x[:], b[(r1-1)*pwxWords:], pwxWords)
	for i := 0; i < r1; i++ {
		blockXOR(x[:], b[i*pwxWords:], pwxWords)
		pwxform(x, ctx)
		blockCopy(b[i*pwxWords:], x[:], pwxWords)
	}
	const i = (r1 - 1) * pwxBytes / 64
	*x = [pwxWords]uint64{}
	salsaXOR(x, b[i*pwxWords:], b[i*pwxWords:], 2)
}

func integer(b []uint64, r int) uint32 {
	return uint32(b[(2*r-1)*8])
}

func p2floor(x uint32) uint32 {
	if x == 0 {
		return 0
	}
	return uint32(1) << (bits.Len32(x) - 1)
}

func wrap(x, i uint32) uint32 {
	n := p2floor(i)
	return (x & (n - 1)) + (i - n)
}

func smixClassic(b []byte, r, n, nloop int, v, xy []uint64) {
	var tmp [8]uint64
	rWords := 16 * r
	x := xy
	y := xy[rWords:]

	j := 0
	for i := 0; i < rWords; i++ {
		lo := binary.LittleEndian.Uint32(b[(j&^63)|((j*5)&63):])
		j += 4
		hi := binary.LittleEndian.Uint32(b[(j&^63)|((j*5)&63):])
		j += 4
		x[i] = uint64(lo) | uint64(hi)<<32
	}
	for i := 0; i < n; i += 2 {
		blockCopy(v[i*rWords:], x, rWords)
		blockMix(&tmp, x, y, r)

		blockCopy(v[(i+1)*rWords:], y, rWords)
		blockMix(&tmp, y, x, r)
	}
	for i := 0; i < nloop; i += 2 {
		j := int(integer(x, r) & uint32(n-1))
		blockXOR(x, v[j*rWords:], rWords)
		blockMix(&tmp, x, y, r)

		j = int(integer(y, r) & uint32(n-1))
		blockXOR(y, v[j*rWords:], rWords)
		blockMix(&tmp, y, x, r)
	}
	j = 0
	for _, word := range x[:rWords] {
		binary.LittleEndian.PutUint32(b[(j&^63)|((j*5)&63):], uint32(word))
		j += 4
		binary.LittleEndian.PutUint32(b[(j&^63)|((j*5)&63):], uint32(word>>32))
		j += 4
	}
}

// smixYescryptCore specializes the memory-hard pass for r=8. Keeping the
// 128-word block size constant lets the compiler remove repeated arithmetic
// and most bounds checks from the two long loops.
func smixYescryptCore(b []byte, n, nloop int, v, xy []uint64, ctx *pwxformCtx) {
	const rWords = 16 * r
	var tmp [pwxWords]uint64
	x := (*[rWords]uint64)(xy)

	j := 0
	for i := range rWords {
		lo := binary.LittleEndian.Uint32(b[(j&^63)|((j*5)&63):])
		j += 4
		hi := binary.LittleEndian.Uint32(b[(j&^63)|((j*5)&63):])
		j += 4
		x[i] = uint64(lo) | uint64(hi)<<32
	}

	for i := 0; i < n; i++ {
		blockCopy(v[i*rWords:], x[:], rWords)
		if i > 1 {
			j := int(wrap(uint32(x[120]), uint32(i)))
			blockXOR(x[:], v[j*rWords:], rWords)
		}
		blockMixPwxform(&tmp, x[:], ctx)
	}
	for range nloop {
		j := int(uint32(x[120]) & uint32(n-1))
		blockXOR(x[:], v[j*rWords:], rWords)
		blockCopy(v[j*rWords:], x[:], rWords)
		blockMixPwxform(&tmp, x[:], ctx)
	}

	j = 0
	for _, word := range x {
		binary.LittleEndian.PutUint32(b[(j&^63)|((j*5)&63):], uint32(word))
		j += 4
		binary.LittleEndian.PutUint32(b[(j&^63)|((j*5)&63):], uint32(word>>32))
		j += 4
	}
}

func smixYescrypt(b []byte, r, n int, v, xy []uint64, passwordSHA256 []byte) {
	var ctx pwxformCtx
	var s [sWords]uint64
	smixClassic(b, 1, sWords/16, 0, s[:], xy)
	ctx.s2 = (*sTable)(s[:sTableLen])
	ctx.s1 = (*sTable)(s[sTableLen : 2*sTableLen])
	ctx.s0 = (*sTable)(s[2*sTableLen:])
	h := hmac.New(sha256.New, b[64*(2*r-1):])
	h.Write(passwordSHA256)
	copy(passwordSHA256, h.Sum(nil))
	smixYescryptCore(b, n, ((n+2)/3+1)&^1, v, xy, &ctx)
}

// Key derives a 32- or 64-byte key using the only yescrypt parameter set used
// by GOST yescrypt: N=32768, r=8, p=1.
func Key(password, salt []byte, keyLen int) ([]byte, error) {
	if keyLen != 32 && keyLen != 64 {
		return nil, errors.New("yescrypt: key length must be 32 or 64 bytes")
	}

	passwordInput := &password
	pass := 0
	n := N >> 6
	prehash := []byte("yescrypt-prehash")
	v := make([]uint64, 16*N*r)
	xy := make([]uint64, 16*r)
	var key []byte

	for pass <= 1 {
		if pass == 1 {
			prehash = prehash[:8]
		}

		h := hmac.New(sha256.New, prehash)
		h.Write(*passwordInput)
		passwordSHA256 := h.Sum(nil)
		passwordInput = &passwordSHA256

		b := pbkdf2.Key(*passwordInput, salt, 1, 128*r, sha256.New)
		copy(*passwordInput, b[:32])
		smixYescrypt(b, r, n, v, xy, *passwordInput)
		key = pbkdf2.Key(*passwordInput, b, 1, keyLen, sha256.New)

		if pass == 0 {
			copy(*passwordInput, key[:32])
			n = N
		} else {
			h1 := hmac.New(sha256.New, key[:32])
			h1.Write([]byte("Client Key"))
			h2 := sha256.New()
			h2.Write(h1.Sum(nil))
			copy(key, h2.Sum(nil))
		}
		pass++
	}

	return key, nil
}
