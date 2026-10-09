package gost34112012256

import (
	"encoding/binary"
)

type TLSTreeParams [3]uint64

var (
	TLSGOSTR341112256WithMagmaCTROMAC TLSTreeParams = TLSTreeParams{
		binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xC0, 0x00, 0x00, 0x00, 0x00}),
		binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0x00, 0x00, 0x00}),
		binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF0, 0x00}),
	}
	TLSGOSTR341112256WithKuznyechikCTROMAC TLSTreeParams = TLSTreeParams{
		binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00}),
		binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF8, 0x00, 0x00}),
		binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC0}),
	}
	TLSGOSTR341112256WithKuznyechikMGML TLSTreeParams = TLSTreeParams{
		binary.BigEndian.Uint64([]byte{0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
		binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xF0, 0x00, 0x00, 0x00, 0x00}),
		binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xE0, 0x00}),
	}
	TLSGOSTR341112256WithMagmaMGML TLSTreeParams = TLSTreeParams{
		binary.BigEndian.Uint64([]byte{0xFF, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
		binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xC0, 0x00, 0x00, 0x00}),
		binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x80}),
	}
	TLSGOSTR341112256WithKuznyechikMGMS TLSTreeParams = TLSTreeParams{
		binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xE0, 0x00, 0x00, 0x00}),
		binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00}),
		binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF8}),
	}
	TLSGOSTR341112256WithMagmaMGMS TLSTreeParams = TLSTreeParams{
		binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFC, 0x00, 0x00, 0x00}),
		binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xE0, 0x00}),
		binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}),
	}
)

type TLSTree struct {
	seq         [8]byte
	keyLevel1   [Size]byte
	keyLevel2   [Size]byte
	key         [Size]byte
	kdf1        KDF
	kdf2        KDF
	kdf3        KDF
	params      TLSTreeParams
	maskedPrev  TLSTreeParams
	initialized bool
}

func NewTLSTree(params TLSTreeParams, keyRoot []byte) *TLSTree {
	t := new(TLSTree)
	t.Reset(params, keyRoot)
	return t
}

// Reset installs a new root key and invalidates all cached levels. It allows
// TLS traffic-secret transitions to reuse the TLSTree and its containing AEAD
// without retaining any previous schedule material.
func (t *TLSTree) Reset(params TLSTreeParams, keyRoot []byte) {
	clear(t.seq[:])
	clear(t.keyLevel1[:])
	clear(t.keyLevel2[:])
	clear(t.key[:])
	t.kdf1 = KDF{}
	t.kdf2 = KDF{}
	t.kdf3 = KDF{}
	t.params = params
	t.maskedPrev = TLSTreeParams{}
	t.initialized = false
	// KDF keeps prepared inner and outer Streebog states, so retaining another
	// copy of the root key is unnecessary.
	t.kdf1.SetKey(keyRoot)
}

func (t *TLSTree) DeriveCached(seqNum uint64) ([]byte, bool) {
	masked := TLSTreeParams{
		seqNum & t.params[0],
		seqNum & t.params[1],
		seqNum & t.params[2],
	}
	if t.initialized && seqNum > 0 && masked == t.maskedPrev {
		return t.key[:], true
	}

	if !t.initialized || masked[0] != t.maskedPrev[0] {
		binary.BigEndian.PutUint64(t.seq[:], masked[0])
		t.kdf1.DeriveInto(t.keyLevel1[:0], kdfLevel1, t.seq[:])
		t.kdf2.SetKey(t.keyLevel1[:])

		binary.BigEndian.PutUint64(t.seq[:], masked[1])
		t.kdf2.DeriveInto(t.keyLevel2[:0], kdfLevel2, t.seq[:])
		t.kdf3.SetKey(t.keyLevel2[:])
	} else if masked[1] != t.maskedPrev[1] {
		binary.BigEndian.PutUint64(t.seq[:], masked[1])
		t.kdf2.DeriveInto(t.keyLevel2[:0], kdfLevel2, t.seq[:])
		t.kdf3.SetKey(t.keyLevel2[:])
	}

	// The level-three KDF is the only operation required for the frequent
	// short-profile rekeys. Repeated sequence zero intentionally still reports
	// a cache miss, matching the historical public DeriveCached contract.
	binary.BigEndian.PutUint64(t.seq[:], masked[2])
	t.kdf3.DeriveInto(t.key[:0], kdfLevel3, t.seq[:])
	t.maskedPrev = masked
	t.initialized = true
	return t.key[:], false
}

func (t *TLSTree) DeriveInto(dst []byte, seqNum uint64) []byte {
	key, _ := t.DeriveCached(seqNum)
	return append(dst, key...)
}

func (t *TLSTree) Derive(seqNum uint64) []byte {
	keyDerived := make([]byte, Size)
	return t.DeriveInto(keyDerived[:0], seqNum)
}
