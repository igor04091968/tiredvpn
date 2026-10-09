package gost28147

import (
	"crypto/cipher"
	"errors"
)

// CryptoProMeshingPeriod is the RFC 4357 key-meshing interval in bytes.
const CryptoProMeshingPeriod = 1024

var cryptoProMeshingConstant = [KeySize]byte{
	0x69, 0x00, 0x72, 0x22, 0x64, 0xc9, 0x04, 0x23,
	0x8d, 0x3a, 0xdb, 0x96, 0x46, 0xe9, 0x2a, 0xc4,
	0x18, 0xfe, 0xac, 0x94, 0x00, 0xed, 0x07, 0x12,
	0xc0, 0x86, 0xdc, 0xc2, 0xef, 0x4c, 0xa9, 0x2b,
}

// MeshedCFB implements full-block CFB with CryptoPro key meshing (RFC 4357).
// It is a stateful stream and must not be used concurrently.
type MeshedCFB struct {
	key       [KeySize]byte
	sbox      *Sbox
	block     Cipher
	encrypt   CFBEncrypter
	decrypt   CFBDecrypter
	isDecrypt bool
	used      int
}

func newMeshedCFB(key []byte, sbox *Sbox, iv []byte, decrypt bool) (*MeshedCFB, error) {
	if len(key) != KeySize || len(iv) != BlockSize || sbox == nil {
		return nil, errors.New("gogost/gost28147: invalid meshed CFB parameters")
	}
	m := &MeshedCFB{sbox: sbox, isDecrypt: decrypt}
	copy(m.key[:], key)
	m.block.SetKey(m.key[:], sbox)
	if decrypt {
		m.decrypt.c = &m.block
		copy(m.decrypt.iv[:], iv)
		m.decrypt.gammaOf = BlockSize
	} else {
		m.encrypt.c = &m.block
		copy(m.encrypt.iv[:], iv)
		m.encrypt.gammaOf = BlockSize
	}
	return m, nil
}

// NewMeshedCFBEncrypter constructs CryptoPro-meshed CFB encryption.
func NewMeshedCFBEncrypter(key []byte, sbox *Sbox, iv []byte) (*MeshedCFB, error) {
	return newMeshedCFB(key, sbox, iv, false)
}

// NewMeshedCFBDecrypter constructs CryptoPro-meshed CFB decryption.
func NewMeshedCFBDecrypter(key []byte, sbox *Sbox, iv []byte) (*MeshedCFB, error) {
	return newMeshedCFB(key, sbox, iv, true)
}

var _ cipher.Stream = (*MeshedCFB)(nil)

func (m *MeshedCFB) rekey() {
	var nextKey [KeySize]byte
	for offset := 0; offset < KeySize; offset += BlockSize {
		m.block.Decrypt(nextKey[offset:offset+BlockSize], cryptoProMeshingConstant[offset:offset+BlockSize])
	}
	var feedback [BlockSize]byte
	if m.isDecrypt {
		feedback = m.decrypt.iv
	} else {
		feedback = m.encrypt.iv
	}
	clear(m.key[:])
	m.key = nextKey
	m.block.SetKey(m.key[:], m.sbox)
	m.block.Encrypt(feedback[:], feedback[:])
	if m.isDecrypt {
		m.decrypt.iv = feedback
		clear(m.decrypt.gamma[:])
		m.decrypt.gammaOf = BlockSize
	} else {
		m.encrypt.iv = feedback
		clear(m.encrypt.gamma[:])
		m.encrypt.gammaOf = BlockSize
	}
	m.used = 0
}

func (m *MeshedCFB) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("gogost/gost28147: meshed CFB destination too short")
	}
	for len(src) > 0 {
		if m.used == CryptoProMeshingPeriod {
			m.rekey()
		}
		n := min(len(src), CryptoProMeshingPeriod-m.used)
		if m.isDecrypt {
			m.decrypt.XORKeyStream(dst[:n], src[:n])
		} else {
			m.encrypt.XORKeyStream(dst[:n], src[:n])
		}
		m.used += n
		dst, src = dst[n:], src[n:]
	}
}
