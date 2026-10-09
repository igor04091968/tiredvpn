package modes_test

import (
	"bytes"
	"crypto/cipher"
	"testing"

	"gitverse.ru/uzer_007/gogost/v3/gost3412128"
	"gitverse.ru/uzer_007/gogost/v3/gost3413/modes"
)

func TestACPKMMasterDerivation(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i*7 + 1)
	}
	out := make([]byte, 64)
	if err := modes.DeriveACPKMMasterInto(out, key, modes.AlgorithmKuznechik, 32); err != nil {
		t.Fatal(err)
	}
	block := gost3412128.NewCipher(key)
	iv := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0}
	wantFirst := make([]byte, 32)
	cipher.NewCTR(block, iv).XORKeyStream(wantFirst, wantFirst)
	if !bytes.Equal(out[:32], wantFirst) {
		t.Fatal("first master section mismatch")
	}
	var nextKey [32]byte
	for offset := 0; offset < 32; offset += 16 {
		input := make([]byte, 16)
		for i := range input {
			input[i] = byte(0x80 + offset + i)
		}
		block.Encrypt(nextKey[offset:offset+16], input)
	}
	iv[15] = 2
	second := make([]byte, 32)
	cipher.NewCTR(gost3412128.NewCipher(nextKey[:]), iv).XORKeyStream(second, second)
	if !bytes.Equal(out[32:], second) {
		t.Fatal("master rekey section mismatch")
	}
	if err := modes.DeriveACPKMMasterInto(out[:31], key, modes.AlgorithmKuznechik, 32); err == nil {
		t.Fatal("partial key accepted")
	}
}
