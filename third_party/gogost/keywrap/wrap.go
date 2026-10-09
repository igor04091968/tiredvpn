// Package keywrap предоставляет функции заворачивания ключей на ГОСТ-алгоритмах,
// возвращающие ошибки вместо panic.
package keywrap

import (
	"crypto/cipher"
	"crypto/hmac"
	"errors"

	"gitverse.ru/uzer_007/gogost/v3/gost28147"
	"gitverse.ru/uzer_007/gogost/v3/gost3412128"
	"gitverse.ru/uzer_007/gogost/v3/gost341264"
	"gitverse.ru/uzer_007/gogost/v3/gost3413/modes"
	"gitverse.ru/uzer_007/gogost/v3/internal/errx"
)

const (
	UKMSize          = 8
	CEKSize          = 32
	LegacyTagSize    = 4
	LegacyWrappedLen = UKMSize + CEKSize + LegacyTagSize
)

var (
	ErrInvalidAlgorithm      = errors.New("gogost/keywrap: Некорректный алгоритм")
	ErrInvalidKEKSize        = errors.New("gogost/keywrap: Некорректный размер KEK")
	ErrInvalidCEKSize        = errors.New("gogost/keywrap: Некорректный размер CEK")
	ErrInvalidUKMSize        = errors.New("gogost/keywrap: Некорректный размер UKM")
	ErrInvalidTagSize        = errors.New("gogost/keywrap: Некорректный размер тега")
	ErrInvalidWrappedKeySize = errors.New("gogost/keywrap: Некорректный размер завёрнутого ключа")
	ErrInvalidMAC            = errors.New("gogost/keywrap: Некорректный MAC")
)

type Algorithm uint8

const (
	AlgorithmUnknown Algorithm = iota
	AlgorithmGost28147
	AlgorithmCryptoPro
	AlgorithmMagma
	AlgorithmKuznechik
)

// Config задаёт алгоритм и параметры заворачивания ключа.
type Config struct {
	Algorithm Algorithm
	KEK       []byte
	UKM       []byte
	TagSize   int
}

// Wrap заворачивает CEK с алгоритмом и параметрами из cfg.
func Wrap(dst, cek []byte, cfg Config) ([]byte, error) {
	switch cfg.Algorithm {
	case AlgorithmGost28147:
		return WrapGost28147(dst, cfg.UKM, cfg.KEK, cek)
	case AlgorithmCryptoPro:
		return WrapCryptoPro(dst, cfg.UKM, cfg.KEK, cek)
	case AlgorithmMagma:
		return wrapModern(dst, cfg.UKM, cfg.KEK, cek, modes.AlgorithmMagma, cfg.TagSize)
	case AlgorithmKuznechik:
		return wrapModern(dst, cfg.UKM, cfg.KEK, cek, modes.AlgorithmKuznechik, cfg.TagSize)
	default:
		return nil, ErrInvalidAlgorithm
	}
}

// Unwrap разворачивает CEK с алгоритмом и параметрами из cfg.
func Unwrap(dst, wrapped []byte, cfg Config) ([]byte, error) {
	switch cfg.Algorithm {
	case AlgorithmGost28147:
		return UnwrapGost28147(dst, cfg.KEK, wrapped)
	case AlgorithmCryptoPro:
		return UnwrapCryptoPro(dst, cfg.KEK, wrapped)
	case AlgorithmMagma:
		return unwrapModern(dst, cfg.KEK, wrapped, modes.AlgorithmMagma, cfg.TagSize)
	case AlgorithmKuznechik:
		return unwrapModern(dst, cfg.KEK, wrapped, modes.AlgorithmKuznechik, cfg.TagSize)
	default:
		return nil, ErrInvalidAlgorithm
	}
}

// WrapGost28147 заворачивает CEK по исторической схеме ГОСТ 28147-89.
func WrapGost28147(dst, ukm, kek, cek []byte) ([]byte, error) {
	return wrapGost28147WithSbox(dst, ukm, kek, cek, &gost28147.SboxIdGost2814789CryptoProAParamSet)
}

func wrapGost28147WithSbox(dst, ukm, kek, cek []byte, sbox *gost28147.Sbox) ([]byte, error) {
	if err := validateUKM(ukm); err != nil {
		return nil, err
	}
	if err := validateKEK(kek); err != nil {
		return nil, err
	}
	if err := validateCEK(cek); err != nil {
		return nil, err
	}

	c := gost28147.NewCipher(kek, sbox)
	mac, err := c.NewMAC(LegacyTagSize, ukm)
	if err != nil {
		return nil, err
	}
	if _, err = mac.Write(cek); err != nil {
		return nil, err
	}

	cekEnc := make([]byte, CEKSize)
	c.NewECBEncrypter().CryptBlocks(cekEnc, cek)
	ret, out := sliceForAppend(dst, LegacyWrappedLen)
	copy(out, ukm)
	copy(out[UKMSize:], cekEnc)
	copy(out[UKMSize+CEKSize:], mac.Sum(nil))
	return ret, nil
}

// UnwrapGost28147 разворачивает CEK по исторической схеме ГОСТ 28147-89.
func UnwrapGost28147(dst, kek, wrapped []byte) ([]byte, error) {
	return unwrapGost28147WithSbox(dst, kek, wrapped, &gost28147.SboxIdGost2814789CryptoProAParamSet)
}

func unwrapGost28147WithSbox(dst, kek, wrapped []byte, sbox *gost28147.Sbox) ([]byte, error) {
	if err := validateKEK(kek); err != nil {
		return nil, err
	}
	if len(wrapped) != LegacyWrappedLen {
		return nil, errx.Wrap(ErrInvalidWrappedKeySize, errx.GotWant(len(wrapped), LegacyWrappedLen))
	}

	ukm := wrapped[:UKMSize]
	cekEnc := wrapped[UKMSize : UKMSize+CEKSize]
	cekMac := wrapped[UKMSize+CEKSize:]
	c := gost28147.NewCipher(kek, sbox)
	cek := make([]byte, CEKSize)
	c.NewECBDecrypter().CryptBlocks(cek, cekEnc)

	mac, err := c.NewMAC(LegacyTagSize, ukm)
	if err != nil {
		return nil, err
	}
	if _, err = mac.Write(cek); err != nil {
		return nil, err
	}
	if !hmac.Equal(mac.Sum(nil), cekMac) {
		return nil, ErrInvalidMAC
	}

	ret, out := sliceForAppend(dst, len(cek))
	copy(out, cek)
	return ret, nil
}

// WrapCryptoPro заворачивает CEK по схеме CryptoPro с диверсификацией KEK.
func WrapCryptoPro(dst, ukm, kek, cek []byte) ([]byte, error) {
	return WrapCryptoProWithSbox(dst, ukm, kek, cek, &gost28147.SboxIdGost2814789CryptoProAParamSet)
}

// WrapCryptoProWithSbox wraps CEK with the selected GOST 28147 parameter set.
func WrapCryptoProWithSbox(dst, ukm, kek, cek []byte, sbox *gost28147.Sbox) ([]byte, error) {
	if sbox == nil {
		return nil, ErrInvalidAlgorithm
	}
	if err := validateUKM(ukm); err != nil {
		return nil, err
	}
	if err := validateKEK(kek); err != nil {
		return nil, err
	}
	return wrapGost28147WithSbox(dst, ukm, diversifyCryptoPro(kek, ukm, sbox), cek, sbox)
}

// UnwrapCryptoPro разворачивает CEK по схеме CryptoPro с диверсификацией KEK.
func UnwrapCryptoPro(dst, kek, wrapped []byte) ([]byte, error) {
	return UnwrapCryptoProWithSbox(dst, kek, wrapped, &gost28147.SboxIdGost2814789CryptoProAParamSet)
}

// UnwrapCryptoProWithSbox unwraps CEK with the selected parameter set.
func UnwrapCryptoProWithSbox(dst, kek, wrapped []byte, sbox *gost28147.Sbox) ([]byte, error) {
	if sbox == nil {
		return nil, ErrInvalidAlgorithm
	}
	if err := validateKEK(kek); err != nil {
		return nil, err
	}
	if len(wrapped) != LegacyWrappedLen {
		return nil, errx.Wrap(ErrInvalidWrappedKeySize, errx.GotWant(len(wrapped), LegacyWrappedLen))
	}
	return unwrapGost28147WithSbox(dst, diversifyCryptoPro(kek, wrapped[:UKMSize], sbox), wrapped, sbox)
}

// WrapMagma заворачивает CEK с использованием Магмы и MAC ГОСТ 34.13.
func WrapMagma(dst, ukm, kek, cek []byte) ([]byte, error) {
	return wrapModern(dst, ukm, kek, cek, modes.AlgorithmMagma, 0)
}

// UnwrapMagma разворачивает CEK с использованием Магмы и MAC ГОСТ 34.13.
func UnwrapMagma(dst, kek, wrapped []byte) ([]byte, error) {
	return unwrapModern(dst, kek, wrapped, modes.AlgorithmMagma, 0)
}

// WrapKuznechik заворачивает CEK с использованием Кузнечика и MAC ГОСТ 34.13.
func WrapKuznechik(dst, ukm, kek, cek []byte) ([]byte, error) {
	return wrapModern(dst, ukm, kek, cek, modes.AlgorithmKuznechik, 0)
}

// UnwrapKuznechik разворачивает CEK с использованием Кузнечика и MAC ГОСТ 34.13.
func UnwrapKuznechik(dst, kek, wrapped []byte) ([]byte, error) {
	return unwrapModern(dst, kek, wrapped, modes.AlgorithmKuznechik, 0)
}

func wrapModern(dst, ukm, kek, cek []byte, alg modes.Algorithm, tagSize int) ([]byte, error) {
	if err := validateUKM(ukm); err != nil {
		return nil, err
	}
	if err := validateKEK(kek); err != nil {
		return nil, err
	}
	if err := validateCEK(cek); err != nil {
		return nil, err
	}
	tagSize, err := normalizeTagSize(alg, tagSize)
	if err != nil {
		return nil, err
	}

	block, err := wrapBlock(alg, kek)
	if err != nil {
		return nil, err
	}
	ret, out := sliceForAppend(dst, UKMSize+CEKSize+tagSize)
	copy(out, ukm)
	cryptECB(block, out[UKMSize:UKMSize+CEKSize], cek, true)
	macCtx, err := modes.NewMAC(block, tagSize)
	if err != nil {
		return nil, err
	}
	macCtx.Sum(out[UKMSize+CEKSize:UKMSize+CEKSize], out[:UKMSize+CEKSize])
	return ret, nil
}

func unwrapModern(dst, kek, wrapped []byte, alg modes.Algorithm, tagSize int) ([]byte, error) {
	if err := validateKEK(kek); err != nil {
		return nil, err
	}
	tagSize, err := normalizeTagSize(alg, tagSize)
	if err != nil {
		return nil, err
	}
	want := UKMSize + CEKSize + tagSize
	if len(wrapped) != want {
		return nil, errx.Wrap(ErrInvalidWrappedKeySize, errx.GotWant(len(wrapped), want))
	}

	block, err := wrapBlock(alg, kek)
	if err != nil {
		return nil, err
	}
	header := wrapped[:UKMSize+CEKSize]
	tag := wrapped[UKMSize+CEKSize:]
	macCtx, err := modes.NewMAC(block, tagSize)
	if err != nil {
		return nil, err
	}
	var expected [gost3412128.BlockSize]byte
	macCtx.Sum(expected[:0], header)
	if !hmac.Equal(expected[:tagSize], tag) {
		return nil, ErrInvalidMAC
	}

	ret, out := sliceForAppend(dst, CEKSize)
	cryptECB(block, out, wrapped[UKMSize:UKMSize+CEKSize], false)
	return ret, nil
}

func wrapBlock(alg modes.Algorithm, key []byte) (cipher.Block, error) {
	switch alg {
	case modes.AlgorithmMagma:
		return gost341264.NewCipher(key), nil
	case modes.AlgorithmKuznechik:
		return gost3412128.NewCipher(key), nil
	default:
		return nil, ErrInvalidAlgorithm
	}
}

func cryptECB(block cipher.Block, dst, src []byte, encrypt bool) {
	if bulk, ok := block.(interface {
		EncryptBlocks(dst, src []byte)
		DecryptBlocks(dst, src []byte)
	}); ok && len(src) >= 4*block.BlockSize() {
		if encrypt {
			bulk.EncryptBlocks(dst, src)
		} else {
			bulk.DecryptBlocks(dst, src)
		}
		return
	}
	blockSize := block.BlockSize()
	for offset := 0; offset < len(src); offset += blockSize {
		if encrypt {
			block.Encrypt(dst[offset:offset+blockSize], src[offset:offset+blockSize])
		} else {
			block.Decrypt(dst[offset:offset+blockSize], src[offset:offset+blockSize])
		}
	}
}

func normalizeTagSize(alg modes.Algorithm, tagSize int) (int, error) {
	blockSize, err := blockSize(alg)
	if err != nil {
		return 0, err
	}
	if tagSize == 0 {
		return blockSize, nil
	}
	if tagSize < LegacyTagSize || tagSize > blockSize {
		return 0, errx.Wrap(ErrInvalidTagSize, errx.GotWantRange(tagSize, LegacyTagSize, blockSize))
	}
	return tagSize, nil
}

func blockSize(alg modes.Algorithm) (int, error) {
	switch alg {
	case modes.AlgorithmMagma:
		return gost341264.BlockSize, nil
	case modes.AlgorithmKuznechik:
		return gost3412128.BlockSize, nil
	default:
		return 0, ErrInvalidAlgorithm
	}
}

func validateKEK(kek []byte) error {
	if len(kek) != gost28147.KeySize {
		return errx.Wrap(ErrInvalidKEKSize, errx.GotWant(len(kek), gost28147.KeySize))
	}
	return nil
}

func validateCEK(cek []byte) error {
	if len(cek) != CEKSize {
		return errx.Wrap(ErrInvalidCEKSize, errx.GotWant(len(cek), CEKSize))
	}
	return nil
}

func validateUKM(ukm []byte) error {
	if len(ukm) != UKMSize {
		return errx.Wrap(ErrInvalidUKMSize, errx.GotWant(len(ukm), UKMSize))
	}
	return nil
}

func diversifyCryptoPro(kek, ukm []byte, sbox *gost28147.Sbox) []byte {
	diversified := append([]byte(nil), kek...)
	return gost28147.DiversifyCryptoProWithSbox(diversified, ukm, sbox)
}

func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
