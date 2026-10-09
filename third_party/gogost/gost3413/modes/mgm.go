package modes

import (
	"crypto/cipher"

	"gitverse.ru/uzer_007/gogost/v3/internal/errx"
	"gitverse.ru/uzer_007/gogost/v3/mgm"
)

// MGM представляет подготовленный режим аутентифицированного шифрования.
type MGM struct {
	aead      cipher.AEAD
	blockSize int
}

func (e engine) MGM(tagSize int) (*MGM, error) {
	if tagSize == 0 {
		tagSize = e.blockSize
	}
	if tagSize < 4 || tagSize > e.blockSize {
		return nil, errx.Wrap(ErrInvalidTagSize, errx.Int(tagSize))
	}
	aead, err := mgm.NewMGM(e.block, tagSize)
	if err != nil {
		return nil, err
	}
	return &MGM{aead: aead, blockSize: e.blockSize}, nil
}

func (m *MGM) Seal(dst, nonce, plaintext, associatedData []byte) ([]byte, error) {
	if err := validateMGMNonce(nonce, m.blockSize); err != nil {
		return nil, err
	}
	if len(plaintext) == 0 && len(associatedData) == 0 {
		return nil, errx.Wrap(ErrInvalidInput, "MGM требует plaintext или associated data")
	}
	return m.aead.Seal(dst, nonce, plaintext, associatedData), nil
}

func (m *MGM) Open(dst, nonce, ciphertext, associatedData []byte) ([]byte, error) {
	if err := validateMGMNonce(nonce, m.blockSize); err != nil {
		return nil, err
	}
	if len(ciphertext) == 0 && len(associatedData) == 0 {
		return nil, errx.Wrap(ErrInvalidInput, "MGM требует ciphertext или associated data")
	}
	plaintext, err := m.aead.Open(dst, nonce, ciphertext, associatedData)
	if err != nil {
		if err == mgm.InvalidTag {
			return nil, ErrAuthFailed
		}
		return nil, err
	}
	return plaintext, nil
}

func validateMGMNonce(nonce []byte, blockSize int) error {
	if len(nonce) != blockSize {
		return errx.Wrap(ErrInvalidIVSize, errx.GotWant(len(nonce), blockSize))
	}
	if nonce[0]&0x80 != 0 {
		return errx.Wrap(ErrInvalidIVSize, "старший бит nonce MGM должен быть нулём")
	}
	return nil
}
