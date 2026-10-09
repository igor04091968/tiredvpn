package gost34112012256

import (
	"errors"

	"gitverse.ru/uzer_007/gogost/v3/internal/gost34112012"
)

type KDF struct {
	inner gost34112012.Hash
	outer gost34112012.Hash
}

var (
	kdfOne    = [1]byte{0x01}
	kdfZero   = [1]byte{0x00}
	kdfLevel1 = []byte("level1")
	kdfLevel2 = []byte("level2")
	kdfLevel3 = []byte("level3")
)

func NewKDF(key []byte) *KDF {
	var kdf KDF
	kdf.SetKey(key)
	return &kdf
}

func (kdf *KDF) SetKey(key []byte) {
	var keyBlock, ipad, opad [BlockSize]byte
	if len(key) > BlockSize {
		sum := gost34112012.Sum256(key)
		copy(keyBlock[:], sum[:])
	} else {
		copy(keyBlock[:], key)
	}
	for i := range BlockSize {
		ipad[i] = keyBlock[i] ^ 0x36
		opad[i] = keyBlock[i] ^ 0x5c
	}
	kdf.inner = gost34112012.NewValue(Size)
	kdf.outer = gost34112012.NewValue(Size)
	_, _ = kdf.inner.Write(ipad[:])
	_, _ = kdf.outer.Write(opad[:])
}

func (kdf *KDF) DeriveInto(dst, label, seed []byte) []byte {
	inner := kdf.inner
	_, _ = inner.Write(kdfOne[:])
	_, _ = inner.Write(label)
	_, _ = inner.Write(kdfZero[:])
	_, _ = inner.Write(seed)
	_, _ = inner.Write(kdfOne[:])
	_, _ = inner.Write(kdfZero[:])
	var innerDigest [Size]byte
	inner.Sum(innerDigest[:0])

	outer := kdf.outer
	_, _ = outer.Write(innerDigest[:])
	return outer.Sum(dst)
}

func (kdf *KDF) Derive(dst, label, seed []byte) (r []byte) {
	return kdf.DeriveInto(dst, label, seed)
}

// DeriveTreeInto implements KDF_TREE_GOSTR3411_2012_256 from RFC 7836.
// dst is filled in place. counterBytes must be between 1 and 4; a protocol
// must specify label, seed and counterBytes rather than choosing them ad hoc.
func (kdf *KDF) DeriveTreeInto(dst, label, seed []byte, counterBytes int) error {
	if kdf == nil || counterBytes < 1 || counterBytes > 4 || len(dst) == 0 || len(dst) > int(^uint(0)>>1)/8 {
		return errors.New("gogost/gost34112012256: Некорректные параметры KDF_TREE")
	}
	blocks := (uint64(len(dst)) + Size - 1) / Size
	if blocks > (uint64(1)<<(8*counterBytes))-1 {
		return errors.New("gogost/gost34112012256: Превышена длина KDF_TREE")
	}
	var length [8]byte
	bits := uint64(len(dst)) * 8
	start := len(length)
	for bits != 0 {
		start--
		length[start] = byte(bits)
		bits >>= 8
	}
	var counter [4]byte
	var innerDigest, block [Size]byte
	for i := uint64(1); i <= blocks; i++ {
		value := i
		for j := counterBytes - 1; j >= 0; j-- {
			counter[j] = byte(value)
			value >>= 8
		}
		inner := kdf.inner
		_, _ = inner.Write(counter[:counterBytes])
		_, _ = inner.Write(label)
		_, _ = inner.Write(kdfZero[:])
		_, _ = inner.Write(seed)
		_, _ = inner.Write(length[start:])
		inner.Sum(innerDigest[:0])
		outer := kdf.outer
		_, _ = outer.Write(innerDigest[:])
		outer.Sum(block[:0])
		copy(dst[(i-1)*Size:], block[:])
	}
	return nil
}
