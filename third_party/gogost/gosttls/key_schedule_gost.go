// Copyright 2026 gogost authors. All rights reserved.
// Use of this source code is governed by the license in the LICENSE file.

package gosttls

import (
	"encoding/binary"
	"hash"

	streebog "gitverse.ru/uzer_007/gogost/v3/internal/gost34112012"
)

const (
	gostHKDFHashSize  = 32
	gostHKDFBlockSize = 64
	maxHKDFLabelSize  = 2 + 1 + 255 + 1 + 255
)

type gostHMAC256 struct {
	inner streebog.Hash
	outer streebog.Hash
}

func gostHashSum(h hash.Hash) (digest [gostHKDFHashSize]byte) {
	if concrete, ok := h.(*streebog.Hash); ok {
		concrete.Sum256Into(&digest)
		return digest
	}
	copy(digest[:], h.Sum(nil))
	return digest
}

func gostHashSumBytes(input []byte) [gostHKDFHashSize]byte {
	return streebog.Sum256(input)
}

func (h *gostHMAC256) reset(key []byte) {
	var keyBlock, ipad, opad [gostHKDFBlockSize]byte
	if len(key) > gostHKDFBlockSize {
		sum := streebog.Sum256(key)
		copy(keyBlock[:], sum[:])
		clear(sum[:])
	} else {
		copy(keyBlock[:], key)
	}
	for i := range keyBlock {
		ipad[i] = keyBlock[i] ^ 0x36
		opad[i] = keyBlock[i] ^ 0x5c
	}
	h.inner = streebog.NewValue(gostHKDFHashSize)
	h.outer = streebog.NewValue(gostHKDFHashSize)
	_, _ = h.inner.Write(ipad[:])
	_, _ = h.outer.Write(opad[:])
	clear(keyBlock[:])
	clear(ipad[:])
	clear(opad[:])
}

func (h *gostHMAC256) sum3(first, second, third []byte) (out [gostHKDFHashSize]byte) {
	inner := h.inner
	_, _ = inner.Write(first)
	_, _ = inner.Write(second)
	_, _ = inner.Write(third)
	var innerDigest [gostHKDFHashSize]byte
	inner.Sum256Into(&innerDigest)
	outer := h.outer
	_, _ = outer.Write(innerDigest[:])
	outer.Sum256Into(&out)
	clear(innerDigest[:])
	return out
}

func gostHKDFExtract(secret, salt []byte) []byte {
	var hmac gostHMAC256
	hmac.reset(salt)
	digest := hmac.sum3(secret, nil, nil)
	out := make([]byte, gostHKDFHashSize)
	copy(out, digest[:])
	clear(digest[:])
	return out
}

func gostHKDFExpand(secret, info []byte, length int) []byte {
	if length < 0 || length > 255*gostHKDFHashSize {
		panic("gosttls: GOST HKDF output length exceeds RFC 5869 limit")
	}
	out := make([]byte, length)
	if length == 0 {
		return out
	}
	var hmac gostHMAC256
	hmac.reset(secret)
	var previous [gostHKDFHashSize]byte
	previousLength := 0
	written := 0
	for counter := byte(1); written < length; counter++ {
		counterBytes := [1]byte{counter}
		block := hmac.sum3(previous[:previousLength], info, counterBytes[:])
		n := copy(out[written:], block[:])
		written += n
		previous = block
		previousLength = len(previous)
		clear(block[:])
	}
	clear(previous[:])
	return out
}

func gostExpandLabel(secret []byte, label string, context []byte, length int) []byte {
	labelLength := len("tls13 ") + len(label)
	if length < 0 || length > 0xffff || labelLength > 255 || len(context) > 255 {
		panic("gosttls: TLS 1.3 label, context, or output length is invalid")
	}
	var encoded [maxHKDFLabelSize]byte
	binary.BigEndian.PutUint16(encoded[:2], uint16(length))
	position := 2
	encoded[position] = byte(labelLength)
	position++
	position += copy(encoded[position:], "tls13 ")
	position += copy(encoded[position:], label)
	encoded[position] = byte(len(context))
	position++
	position += copy(encoded[position:], context)
	return gostHKDFExpand(secret, encoded[:position], length)
}

func gostFinishedHash(baseKey, transcript []byte) []byte {
	finishedKey := gostExpandLabel(baseKey, "finished", nil, gostHKDFHashSize)
	var hmac gostHMAC256
	hmac.reset(finishedKey)
	digest := hmac.sum3(transcript, nil, nil)
	clear(finishedKey)
	out := make([]byte, gostHKDFHashSize)
	copy(out, digest[:])
	clear(digest[:])
	return out
}
