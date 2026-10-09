package gost28147

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"testing"
)

func TestCipherInterface(t *testing.T) {
	var _ cipher.Block = NewCipher(make([]byte, KeySize), SboxDefault)
}

func TestEncryptBlocks(t *testing.T) {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i*17 + 3)
	}

	c := NewCipher(key, &SboxIdGost2814789CryptoProAParamSet)
	for _, blocks := range []int{1, 2, 3, 4, 5, 6, 8, 9, 16, 17, 128} {
		plaintext := make([]byte, blocks*BlockSize)
		for i := range plaintext {
			plaintext[i] = byte(i*31 + 11)
		}

		want := make([]byte, len(plaintext))
		for off := 0; off < len(plaintext); off += BlockSize {
			c.Encrypt(want[off:off+BlockSize], plaintext[off:off+BlockSize])
		}

		got := make([]byte, len(plaintext))
		c.EncryptBlocks(got, plaintext)
		if !bytes.Equal(got, want) {
			t.Fatalf("EncryptBlocks mismatch for %d blocks", blocks)
		}

		c.DecryptBlocks(got, got)
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("DecryptBlocks round-trip failed for %d blocks", blocks)
		}

		inPlace := append([]byte(nil), plaintext...)
		c.EncryptBlocks(inPlace, inPlace)
		if !bytes.Equal(inPlace, want) {
			t.Fatalf("EncryptBlocks in-place mismatch for %d blocks", blocks)
		}
		c.DecryptBlocks(inPlace, inPlace)
		if !bytes.Equal(inPlace, plaintext) {
			t.Fatalf("DecryptBlocks in-place round-trip failed for %d blocks", blocks)
		}
	}
}

func BenchmarkCipher(b *testing.B) {
	var key [KeySize]byte
	rand.Read(key[:])
	dst := make([]byte, BlockSize)
	src := make([]byte, BlockSize)
	rand.Read(src)
	c := NewCipher(key[:], SboxDefault)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Encrypt(dst, src)
	}
}
func BenchmarkEncrypt(b *testing.B) {
	key := make([]byte, KeySize)
	rand.Read(key)
	c := NewCipher(key, SboxDefault)
	blk := make([]byte, BlockSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Encrypt(blk, blk)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	key := make([]byte, KeySize)
	rand.Read(key)
	c := NewCipher(key, SboxDefault)
	blk := make([]byte, BlockSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Decrypt(blk, blk)
	}
}
