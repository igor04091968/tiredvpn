// Package profiles содержит консервативные высокоуровневые профили для gogost.
package profiles

import (
	"gitverse.ru/uzer_007/gogost/v3/gost3412128"
	"gitverse.ru/uzer_007/gogost/v3/gost3413/modes"
)

// FileEncryptionKuznechikCTRACPKM подготавливает Кузнечик CTR-ACPKM
// с размером секции по умолчанию.
func FileEncryptionKuznechikCTRACPKM(key, iv []byte) (*modes.CTRACPKM, error) {
	engine, err := modes.NewKuznechik(key)
	if err != nil {
		return nil, err
	}
	return engine.CTRACPKM(iv, modes.DefaultACPKMSectionSize)
}

// MessageEncryptionMGM подготавливает Кузнечик MGM с тегом полной длины.
func MessageEncryptionMGM(key []byte) (*modes.MGM, error) {
	engine, err := modes.NewKuznechik(key)
	if err != nil {
		return nil, err
	}
	return engine.MGM(gost3412128.BlockSize)
}
