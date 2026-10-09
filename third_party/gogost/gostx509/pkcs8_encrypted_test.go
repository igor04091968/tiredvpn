package gostx509

import (
	"bytes"
	"encoding/asn1"
	"math/big"
	"os"
	"testing"

	"gitverse.ru/uzer_007/gogost/v3/gost3410"
)

func TestEncryptedPKCS8GOST(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts EncryptedPKCS8Options
	}{{"Kuznechik", EncryptedPKCS8Options{}}, {"Magma", EncryptedPKCS8Options{Magma: true}}, {"Legacy28147", EncryptedPKCS8Options{Legacy28147: true}}} {
		t.Run(tc.name, func(t *testing.T) {
			private, _ := generateKey(t, gost3410.CurveIdtc26gost34102012256paramSetA())
			options := tc.opts
			options.Iterations = 1000
			der, err := MarshalEncryptedPKCS8PrivateKey(private, "пароль", &options)
			if err != nil {
				t.Fatal(err)
			}
			key, err := ParseEncryptedPKCS8PrivateKey(der, "пароль")
			if err != nil {
				t.Fatal(err)
			}
			got, ok := key.(*gost3410.PrivateKey)
			if !ok || !bytes.Equal(got.Raw(), private.Raw()) {
				t.Fatal("wrong key")
			}
			if _, err := ParseEncryptedPKCS8PrivateKey(der, "wrong"); err == nil {
				t.Fatal("wrong password accepted")
			}
			var info encryptedPrivateKeyInfo
			if _, err := asn1.Unmarshal(der, &info); err != nil {
				t.Fatal(err)
			}
			if !options.Legacy28147 {
				info.EncryptedData[len(info.EncryptedData)-1] ^= 1
				tampered, err := asn1.Marshal(info)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := ParseEncryptedPKCS8PrivateKey(tampered, "пароль"); err == nil {
					t.Fatal("tampered ciphertext accepted")
				}
			}
		})
	}
	if _, err := MarshalEncryptedPKCS8PrivateKey(nil, "password", &EncryptedPKCS8Options{Magma: true, Legacy28147: true}); err == nil {
		t.Fatal("conflicting cipher options accepted")
	}
}

func TestCompetitorEncryptedPKCS8(t *testing.T) {
	der, err := os.ReadFile("testdata/competitor-private-key/encrypted.der")
	if err != nil {
		t.Fatal(err)
	}
	key, err := ParseEncryptedPKCS8PrivateKey(der, "interop-password")
	if err != nil {
		t.Fatal(err)
	}
	want, _ := new(big.Int).SetString("0DC8DC1FF2BC114BABC3F1CA8C51E4F58610427E197B1C2FBDBA4AE58CBFB7CE", 16)
	if key.(*gost3410.PrivateKey).Key.Cmp(want) != 0 {
		t.Fatal("competitor private key mismatch")
	}
	if _, err := ParseEncryptedPKCS8PrivateKey(der, "wrong"); err == nil {
		t.Fatal("wrong password accepted")
	}
}
