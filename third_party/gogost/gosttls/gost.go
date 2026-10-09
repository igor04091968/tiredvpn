// Copyright 2026 gogost authors. All rights reserved.
// Use of this source code is governed by the license in the LICENSE file.

package gosttls

import (
	"crypto/cipher"
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"

	"gitverse.ru/uzer_007/gogost/v3/gost3410"
	"gitverse.ru/uzer_007/gogost/v3/gost34112012256"
	"gitverse.ru/uzer_007/gogost/v3/gost3412128"
	"gitverse.ru/uzer_007/gogost/v3/gost341264"
	"gitverse.ru/uzer_007/gogost/v3/mgm"
)

const gostRecordNonceSize = 8

// GOSTCipherSuiteIDs returns the RFC 9367 TLS 1.3 cipher suites in preference
// order. The returned slice is independent and may be modified by the caller.
func GOSTCipherSuiteIDs() []uint16 {
	return []uint16{
		TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L,
		TLS_GOSTR341112_256_WITH_MAGMA_MGM_L,
		TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S,
		TLS_GOSTR341112_256_WITH_MAGMA_MGM_S,
	}
}

// GOSTCurveIDs returns all RFC 9367 GOST R 34.10-2012 named groups.
func GOSTCurveIDs() []CurveID {
	return []CurveID{
		GOSTCurve256A, GOSTCurve256B, GOSTCurve256C, GOSTCurve256D,
		GOSTCurve512C, GOSTCurve512A, GOSTCurve512B,
	}
}

// GOSTSignatureSchemes returns all RFC 9367 GOST signature schemes.
func GOSTSignatureSchemes() []SignatureScheme {
	return []SignatureScheme{
		GOSTR34102012256A, GOSTR34102012256B, GOSTR34102012256C,
		GOSTR34102012256D, GOSTR34102012512A, GOSTR34102012512B,
		GOSTR34102012512C,
	}
}

// GOSTConfig clones base and restricts the result to the RFC 9367 GOST TLS
// 1.3 profile. If base is nil, a new Config is returned.
func GOSTConfig(base *Config) *Config {
	if base == nil {
		base = new(Config)
	} else {
		base = base.Clone()
	}
	base.MinVersion = VersionTLS13
	base.MaxVersion = VersionTLS13
	base.CipherSuitesTLS13 = GOSTCipherSuiteIDs()
	base.CurvePreferences = GOSTCurveIDs()
	base.SignatureSchemes = GOSTSignatureSchemes()
	return base
}

func isGOSTCipherSuite(id uint16) bool {
	return id >= TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L &&
		id <= TLS_GOSTR341112_256_WITH_MAGMA_MGM_S
}

func isGOSTCurve(id CurveID) bool {
	return id >= GOSTCurve256A && id <= GOSTCurve512C
}

type gostAEAD struct {
	nonceMask      [gost3412128.BlockSize]byte
	recordNonceBuf [gost3412128.BlockSize]byte
	nonceSize      int
	tree           gost34112012256.TLSTree
	params         gost34112012256.TLSTreeParams
	block          rekeyableBlock
	aead           cipher.AEAD
	lastSequence   uint64
	keyInitialized bool
}

type rekeyableBlock interface {
	cipher.Block
	SetKey([]byte)
}

func (g *gostAEAD) NonceSize() int        { return gostRecordNonceSize }
func (g *gostAEAD) Overhead() int         { return g.aead.Overhead() }
func (g *gostAEAD) explicitNonceLen() int { return 0 }

func (g *gostAEAD) refreshKey(nonce []byte) {
	if len(nonce) != gostRecordNonceSize {
		panic("gosttls: internal error: invalid GOST record nonce length")
	}
	sequence := binary.BigEndian.Uint64(nonce)
	if g.keyInitialized && sequence == g.lastSequence {
		return
	}
	key, cached := g.tree.DeriveCached(sequence)
	if cached {
		g.lastSequence = sequence
		g.keyInitialized = true
		return
	}
	g.block.SetKey(key)
	g.lastSequence = sequence
	g.keyInitialized = true
}

func (g *gostAEAD) recordNonce(nonce []byte) []byte {
	copy(g.recordNonceBuf[:g.nonceSize], g.nonceMask[:g.nonceSize])
	offset := g.nonceSize - len(nonce)
	for i, b := range nonce {
		g.recordNonceBuf[offset+i] ^= b
	}
	return g.recordNonceBuf[:g.nonceSize]
}

func (g *gostAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	g.refreshKey(nonce)
	recordNonce := g.recordNonce(nonce)
	return g.aead.Seal(dst, recordNonce, plaintext, additionalData)
}

func (g *gostAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	g.refreshKey(nonce)
	recordNonce := g.recordNonce(nonce)
	return g.aead.Open(dst, recordNonce, ciphertext, additionalData)
}

func (g *gostAEAD) reset(key, nonceMask []byte) {
	if len(key) != 32 || len(nonceMask) != g.nonceSize {
		panic("gosttls: internal error: invalid GOST traffic key material")
	}
	clear(g.nonceMask[:])
	clear(g.recordNonceBuf[:])
	g.tree.Reset(g.params, key)
	copy(g.nonceMask[:], nonceMask)
	g.nonceMask[0] &= 0x7f
	g.lastSequence = 0
	g.keyInitialized = false
	var initialSequence [gostRecordNonceSize]byte
	g.refreshKey(initialSequence[:])
}

func newGOSTAEAD(
	params gost34112012256.TLSTreeParams,
	block rekeyableBlock,
	key, nonceMask []byte,
) aead {
	blockSize := block.BlockSize()
	if len(key) != 32 || len(nonceMask) != blockSize {
		panic("gosttls: internal error: invalid GOST traffic key material")
	}
	g := &gostAEAD{
		nonceSize: blockSize,
		params:    params,
		block:     block,
	}
	var err error
	g.aead, err = mgm.NewMGM(block, blockSize)
	if err != nil {
		panic(err)
	}
	// RFC 9367 requires the most significant bit of the MGM nonce to be zero.
	g.reset(key, nonceMask)
	return g
}

func aeadGOSTKuznyechikMGML(key, nonce []byte) aead {
	return newGOSTAEAD(gost34112012256.TLSGOSTR341112256WithKuznyechikMGML,
		gost3412128.NewCipher(key), key, nonce)
}

func aeadGOSTMagmaMGML(key, nonce []byte) aead {
	return newGOSTAEAD(gost34112012256.TLSGOSTR341112256WithMagmaMGML,
		gost341264.NewCipher(key), key, nonce)
}

func aeadGOSTKuznyechikMGMS(key, nonce []byte) aead {
	return newGOSTAEAD(gost34112012256.TLSGOSTR341112256WithKuznyechikMGMS,
		gost3412128.NewCipher(key), key, nonce)
}

func aeadGOSTMagmaMGMS(key, nonce []byte) aead {
	return newGOSTAEAD(gost34112012256.TLSGOSTR341112256WithMagmaMGMS,
		gost341264.NewCipher(key), key, nonce)
}

// tls13KeyShare abstracts standard crypto/ecdh keys and RFC 9367 GOST VKO
// keys without requiring changes to the Go standard library.
type tls13KeyShare interface {
	Group() CurveID
	PublicKeyBytes() []byte
	ECDH(peerPublicKey []byte) ([]byte, error)
}

type standardKeyShare struct {
	group CurveID
	key   *ecdh.PrivateKey
}

func (k *standardKeyShare) Group() CurveID         { return k.group }
func (k *standardKeyShare) PublicKeyBytes() []byte { return k.key.PublicKey().Bytes() }
func (k *standardKeyShare) ECDH(peer []byte) ([]byte, error) {
	public, err := k.key.Curve().NewPublicKey(peer)
	if err != nil {
		return nil, err
	}
	return k.key.ECDH(public)
}

type gostKeyShare struct {
	group  CurveID
	key    *gost3410.PrivateKey
	public []byte
}

func (k *gostKeyShare) Group() CurveID         { return k.group }
func (k *gostKeyShare) PublicKeyBytes() []byte { return append([]byte(nil), k.public...) }

func (k *gostKeyShare) ECDH(peer []byte) ([]byte, error) {
	pointSize := k.key.C.PointSize()
	if len(peer) != 2*pointSize {
		return nil, errors.New("gosttls: invalid GOST key share length")
	}
	public, err := gost3410.NewPublicKey(k.key.C, peer)
	if err != nil {
		return nil, err
	}
	if public.X.Sign() < 0 || public.Y.Sign() < 0 ||
		public.X.Cmp(k.key.C.P) >= 0 || public.Y.Cmp(k.key.C.P) >= 0 ||
		!k.key.C.Contains(public.X, public.Y) {
		return nil, errors.New("gosttls: GOST key share is not on the selected curve")
	}
	sharedPoint, err := k.key.KEK(public, big.NewInt(1))
	if err != nil {
		return nil, err
	}
	if len(sharedPoint) != 2*pointSize {
		return nil, errors.New("gosttls: invalid GOST shared point")
	}
	// RFC 9367 feeds the little-endian X coordinate into HKDF-Extract.
	return append([]byte(nil), sharedPoint[:pointSize]...), nil
}

func gostCurveForID(id CurveID) (*gost3410.Curve, bool) {
	switch id {
	case GOSTCurve256A:
		return gost3410.CurveIdtc26gost341012256paramSetA(), true
	case GOSTCurve256B:
		return gost3410.CurveIdtc26gost341012256paramSetB(), true
	case GOSTCurve256C:
		return gost3410.CurveIdtc26gost341012256paramSetC(), true
	case GOSTCurve256D:
		return gost3410.CurveIdtc26gost341012256paramSetD(), true
	case GOSTCurve512A:
		return gost3410.CurveIdtc26gost341012512paramSetA(), true
	case GOSTCurve512B:
		return gost3410.CurveIdtc26gost341012512paramSetB(), true
	case GOSTCurve512C:
		return gost3410.CurveIdtc26gost341012512paramSetC(), true
	default:
		return nil, false
	}
}

func generateTLS13KeyShare(random io.Reader, group CurveID) (tls13KeyShare, error) {
	if curve, ok := gostCurveForID(group); ok {
		for {
			key, err := gost3410.GenPrivateKey(curve, random)
			if err != nil {
				return nil, err
			}
			// NewPrivateKey reduces modulo Q. Reject the vanishingly unlikely
			// zero result before attempting scalar multiplication.
			if key.Key.Sign() == 0 {
				continue
			}
			public, err := key.PublicKey()
			if err != nil {
				return nil, err
			}
			return &gostKeyShare{group: group, key: key, public: public.Raw()}, nil
		}
	}
	key, err := generateECDHEKey(random, group)
	if err != nil {
		return nil, fmt.Errorf("gosttls: unsupported TLS 1.3 group %d: %w", group, err)
	}
	return &standardKeyShare{group: group, key: key}, nil
}
