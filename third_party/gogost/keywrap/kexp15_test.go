package keywrap_test

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"testing"

	"gitverse.ru/uzer_007/gogost/v3/gost3412128"
	"gitverse.ru/uzer_007/gogost/v3/gost3413/modes"
	"gitverse.ru/uzer_007/gogost/v3/keywrap"
)

func TestKExp15(t *testing.T) {
	macKey := seq(32, 1)
	encKey := seq(32, 2)
	for _, tc := range []struct {
		name      string
		algorithm keywrap.Algorithm
		ivSize    int
		tagSize   int
	}{
		{"Kuznechik", keywrap.AlgorithmKuznechik, 8, 16},
		{"Magma", keywrap.AlgorithmMagma, 4, 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			iv := seq(tc.ivSize, 3)
			secret := seq(47, 4)
			exported, err := keywrap.KExp15(nil, secret, macKey, encKey, iv, tc.algorithm)
			if err != nil {
				t.Fatal(err)
			}
			if len(exported) != len(secret)+tc.tagSize {
				t.Fatal("invalid exported length")
			}
			got, err := keywrap.KImp15(nil, exported, macKey, encKey, iv, tc.algorithm)
			if err != nil || !bytes.Equal(got, secret) {
				t.Fatalf("import: %x %v", got, err)
			}
			exported[0] ^= 1
			if _, err := keywrap.KImp15(nil, exported, macKey, encKey, iv, tc.algorithm); !errors.Is(err, keywrap.ErrInvalidMAC) {
				t.Fatalf("tamper: %v", err)
			}
			if _, err := keywrap.KExp15(nil, secret, macKey, macKey, iv, tc.algorithm); err == nil {
				t.Fatal("equal keys accepted")
			}
		})
	}
}

func TestKExp15KuznechikComposition(t *testing.T) {
	macKey := seq(32, 1)
	encKey := seq(32, 2)
	iv := seq(8, 3)
	secret := seq(41, 4)
	exported, err := keywrap.KExp15(nil, secret, macKey, encKey, iv, keywrap.AlgorithmKuznechik)
	if err != nil {
		t.Fatal(err)
	}
	block := gost3412128.NewCipher(macKey)
	mac, err := modes.NewMAC(block, 16)
	if err != nil {
		t.Fatal(err)
	}
	macInput := append(append([]byte(nil), iv...), secret...)
	plain := append(append([]byte(nil), secret...), mac.Sum(nil, macInput)...)
	encBlock := gost3412128.NewCipher(encKey)
	fullIV := make([]byte, 16)
	copy(fullIV, iv)
	want := make([]byte, len(plain))
	cipher.NewCTR(encBlock, fullIV).XORKeyStream(want, plain)
	if !bytes.Equal(exported, want) {
		t.Fatalf("RFC 9189 composition mismatch: %x != %x", exported, want)
	}
}
