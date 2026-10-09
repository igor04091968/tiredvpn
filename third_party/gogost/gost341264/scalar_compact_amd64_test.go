//go:build amd64 && !purego

package gost341264

import "testing"

func TestMagmaCompactScalarMatchesGo(t *testing.T) {
	for keyNumber := 0; keyNumber < 8; keyNumber++ {
		key := make([]byte, KeySize)
		for i := range key {
			key[i] = byte(i*17 + keyNumber*29 + 3)
		}
		c := NewCipher(key)
		for i := uint64(0); i < 1024; i++ {
			v := i*0x9e3779b97f4a7c15 + uint64(keyNumber*107+11)
			in1, in2 := word(uint32(v)), word(uint32(v>>32))
			got1, got2 := magmaCrypt32CompactEncrypt(&c.baseKeys, c.table, in1, in2)
			want1, want2 := magmaCrypt32EncryptT16(&c.baseKeys, c.t16, in1, in2)
			if got1 != want1 || got2 != want2 {
				t.Fatalf("encrypt mismatch for key %d, input %d: %08x %08x vs %08x %08x", keyNumber, i, got1, got2, want1, want2)
			}
			got1, got2 = magmaCrypt32CompactDecrypt(&c.baseKeys, c.table, in1, in2)
			want1, want2 = magmaCrypt32DecryptT16(&c.baseKeys, c.t16, in1, in2)
			if got1 != want1 || got2 != want2 {
				t.Fatalf("decrypt mismatch for key %d, input %d: %08x %08x vs %08x %08x", keyNumber, i, got1, got2, want1, want2)
			}
		}
	}
}
