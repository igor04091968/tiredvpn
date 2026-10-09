package gost341264

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"testing"
)

func TestCipherInterface(t *testing.T) {
	var _ cipher.Block = NewCipher(make([]byte, KeySize))
}

func TestVector(t *testing.T) {
	key := []byte{
		0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
		0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
		0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
	}
	pt := [BlockSize]byte{0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	ct := [BlockSize]byte{0x4e, 0xe9, 0x01, 0xe5, 0xc2, 0xd8, 0xca, 0x3d}
	c := NewCipher(key)
	dst := make([]byte, BlockSize)
	c.Encrypt(dst, pt[:])
	if !bytes.Equal(dst, ct[:]) {
		t.FailNow()
	}
	c.Decrypt(dst, dst)
	if !bytes.Equal(dst, pt[:]) {
		t.FailNow()
	}
}

func TestCTRRoundTrip(t *testing.T) {
	key := make([]byte, KeySize)
	iv := []byte{0x12, 0x34, 0x56, 0x78}
	for i := range key {
		key[i] = byte(i*19 + 7)
	}

	c := NewCipher(key)
	for _, size := range []int{0, 1, BlockSize - 1, BlockSize, BlockSize + 1, 2 * BlockSize, 3 * BlockSize, 4 * BlockSize, 4*BlockSize + 1, 1025} {
		plaintext := make([]byte, size)
		for i := range plaintext {
			plaintext[i] = byte(i*29 + 5)
		}

		ciphertext := make([]byte, len(plaintext))
		c.XORKeyStreamCTR(ciphertext, plaintext, iv)
		c.XORKeyStreamCTR(ciphertext, ciphertext, iv)
		if !bytes.Equal(ciphertext, plaintext) {
			t.Fatalf("CTR round-trip failed for %d bytes", size)
		}

		inPlace := append([]byte(nil), plaintext...)
		c.XORKeyStreamCTR(inPlace, inPlace, iv)
		c.XORKeyStreamCTR(inPlace, inPlace, iv)
		if !bytes.Equal(inPlace, plaintext) {
			t.Fatalf("CTR in-place round-trip failed for %d bytes", size)
		}
	}
}

func TestCTRSplit(t *testing.T) {
	key := make([]byte, KeySize)
	iv := []byte{0x12, 0x34, 0x56, 0x78}
	for i := range key {
		key[i] = byte(i*19 + 7)
	}
	plaintext := make([]byte, 4096)
	for i := range plaintext {
		plaintext[i] = byte(i*29 + 5)
	}

	c := NewCipher(key)
	want := make([]byte, len(plaintext))
	c.XORKeyStreamCTR(want, plaintext, iv)

	got := make([]byte, len(plaintext))
	var counter [BlockSize]byte
	copy(counter[:], iv)
	cuts := []int{512, 1024, 64, 2048, len(plaintext) - 512 - 1024 - 64 - 2048}
	off := 0
	for _, n := range cuts {
		c.XORKeyStreamCTRCounter(got[off:off+n], plaintext[off:off+n], counter[:])
		off += n
	}
	if !bytes.Equal(got, want) {
		t.Fatal("split CTR stream mismatch")
	}
}

func TestEncryptBlocks(t *testing.T) {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i*19 + 7)
	}

	c := NewCipher(key)
	for _, blocks := range []int{1, 2, 3, 4, 5, 6, 8, 9, 16, 17, 128} {
		plaintext := make([]byte, blocks*BlockSize)
		for i := range plaintext {
			plaintext[i] = byte(i*29 + 5)
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

func BenchmarkEncrypt(b *testing.B) {
	key := make([]byte, KeySize)
	rand.Read(key)
	c := NewCipher(key)
	blk := make([]byte, BlockSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Encrypt(blk, blk)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	key := make([]byte, KeySize)
	rand.Read(key)
	c := NewCipher(key)
	blk := make([]byte, BlockSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Decrypt(blk, blk)
	}
}
