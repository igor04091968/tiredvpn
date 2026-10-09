package gost34112012256

import (
	"crypto/subtle"
)

type ESPTree struct {
	keyLevel1   [Size]byte
	keyLevel2   [Size]byte
	key         [Size]byte
	isPrev      [5]byte
	kdf1        KDF
	kdf2        KDF
	kdf3        KDF
	seed        [2]byte
	initialized bool
}

func NewESPTree(keyRoot []byte) *ESPTree {
	t := new(ESPTree)
	t.kdf1.SetKey(keyRoot)
	t.DeriveCached([]byte{0x00, 0x00, 0x00, 0x00, 0x00})
	return t
}

func (t *ESPTree) DeriveCached(is []byte) ([]byte, bool) {
	if len(is) != 1+2+2 {
		panic("gogost/gost34112012256: Некорректный ввод i1+i2+i3")
	}
	if t.initialized && subtle.ConstantTimeCompare(t.isPrev[:], is) == 1 {
		return t.key[:], true
	}
	if !t.initialized || t.isPrev[0] != is[0] {
		t.seed[0] = 0
		t.seed[1] = is[0]
		t.kdf1.DeriveInto(t.keyLevel1[:0], kdfLevel1, t.seed[:])
		t.kdf2.SetKey(t.keyLevel1[:])
		t.kdf2.DeriveInto(t.keyLevel2[:0], kdfLevel2, is[1:3])
		t.kdf3.SetKey(t.keyLevel2[:])
	} else if subtle.ConstantTimeCompare(t.isPrev[1:3], is[1:3]) != 1 {
		t.kdf2.DeriveInto(t.keyLevel2[:0], kdfLevel2, is[1:3])
		t.kdf3.SetKey(t.keyLevel2[:])
	}
	t.kdf3.DeriveInto(t.key[:0], kdfLevel3, is[3:5])
	copy(t.isPrev[:], is)
	t.initialized = true
	return t.key[:], false
}

func (t *ESPTree) DeriveInto(dst []byte, is []byte) []byte {
	key, _ := t.DeriveCached(is)
	return append(dst, key...)
}

func (t *ESPTree) Derive(is []byte) []byte {
	keyDerived := make([]byte, Size)
	return t.DeriveInto(keyDerived[:0], is)
}
