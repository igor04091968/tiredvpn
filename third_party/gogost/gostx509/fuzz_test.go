package gostx509

import "testing"

func FuzzKeyContainerParsers(f *testing.F) {
	for _, seed := range [][]byte{nil, {0x30, 0x00}, {0x30, 0x80, 0, 0}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = ParsePKCS8PrivateKey(input)
		_, _ = ParseEncryptedPKCS8PrivateKey(input, "password")
		_, _, _, _ = ParsePFX(input, "password")
	})
}
