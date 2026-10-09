package keywrap

import (
	"crypto/hmac"
	"errors"

	"gitverse.ru/uzer_007/gogost/v3/gost3413/modes"
)

// KExp15 exports an arbitrary secret according to RFC 9189 section 8.2.1.
// macKey and encKey must be independent 32-byte keys, and iv must be unique
// for each pair of keys. The IV is supplied separately and is not serialized.
func KExp15(dst, secret, macKey, encKey, iv []byte, algorithm Algorithm) ([]byte, error) {
	mac, ctr, tagSize, err := kexp15Modes(macKey, encKey, iv, algorithm)
	if err != nil {
		return nil, err
	}
	if len(secret) > int(^uint(0)>>1)-tagSize-len(iv) {
		return nil, errors.New("gogost/keywrap: KExp15 secret too large")
	}
	macInput := make([]byte, len(iv)+len(secret))
	copy(macInput, iv)
	copy(macInput[len(iv):], secret)
	tag := mac.Sum(nil, macInput)
	clear(macInput)
	plain := make([]byte, len(secret)+tagSize)
	copy(plain, secret)
	copy(plain[len(secret):], tag)
	result, err := ctr.Encrypt(dst, plain)
	clear(plain)
	return result, err
}

// KImp15 imports an RFC 9189 KExp15 representation and verifies its OMAC
// before returning plaintext. The caller supplies the same IV used on export.
func KImp15(dst, exported, macKey, encKey, iv []byte, algorithm Algorithm) ([]byte, error) {
	mac, ctr, tagSize, err := kexp15Modes(macKey, encKey, iv, algorithm)
	if err != nil {
		return nil, err
	}
	if len(exported) < tagSize {
		return nil, ErrInvalidWrappedKeySize
	}
	plain, err := ctr.Decrypt(nil, exported)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	secret := plain[:len(plain)-tagSize]
	macInput := make([]byte, len(iv)+len(secret))
	copy(macInput, iv)
	copy(macInput[len(iv):], secret)
	expected := mac.Sum(nil, macInput)
	clear(macInput)
	if !hmac.Equal(expected, plain[len(secret):]) {
		return nil, ErrInvalidMAC
	}
	result, out := sliceForAppend(dst, len(secret))
	copy(out, secret)
	return result, nil
}

type kexp15CTR interface {
	Encrypt([]byte, []byte) ([]byte, error)
	Decrypt([]byte, []byte) ([]byte, error)
}

func kexp15Modes(macKey, encKey, iv []byte, algorithm Algorithm) (*modes.MAC, kexp15CTR, int, error) {
	if len(macKey) != 32 || len(encKey) != 32 {
		return nil, nil, 0, ErrInvalidKEKSize
	}
	if hmac.Equal(macKey, encKey) {
		return nil, nil, 0, errors.New("gogost/keywrap: KExp15 requires independent keys")
	}
	switch algorithm {
	case AlgorithmKuznechik:
		if len(iv) != 8 {
			return nil, nil, 0, ErrInvalidUKMSize
		}
		m, err := modes.NewKuznechik(macKey)
		if err != nil {
			return nil, nil, 0, err
		}
		mac, err := m.MAC(16)
		if err != nil {
			return nil, nil, 0, err
		}
		e, err := modes.NewKuznechik(encKey)
		if err != nil {
			return nil, nil, 0, err
		}
		ctr, err := e.CTR(iv)
		return mac, ctr, 16, err
	case AlgorithmMagma:
		if len(iv) != 4 {
			return nil, nil, 0, ErrInvalidUKMSize
		}
		m, err := modes.NewMagma(macKey)
		if err != nil {
			return nil, nil, 0, err
		}
		mac, err := m.MAC(8)
		if err != nil {
			return nil, nil, 0, err
		}
		e, err := modes.NewMagma(encKey)
		if err != nil {
			return nil, nil, 0, err
		}
		ctr, err := e.CTR(iv)
		return mac, ctr, 8, err
	default:
		return nil, nil, 0, ErrInvalidAlgorithm
	}
}
