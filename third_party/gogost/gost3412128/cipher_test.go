package gost3412128

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"testing"
	"testing/quick"
)

var (
	Key []byte = []byte{
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	}
	pt [BlockSize]byte = [BlockSize]byte{
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
		0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
	}
	ct [BlockSize]byte = [BlockSize]byte{
		0x7f, 0x67, 0x9d, 0x90, 0xbe, 0xbc, 0x24, 0x30,
		0x5a, 0x46, 0x8d, 0x42, 0xb9, 0xd4, 0xed, 0xcd,
	}

	blockBenchSink [BlockSize]byte
)

func TestCipherInterface(t *testing.T) {
	var _ cipher.Block = NewCipher(make([]byte, KeySize))
}

func TestRandom(t *testing.T) {
	data := make([]byte, BlockSize)
	f := func(key [KeySize]byte, pt [BlockSize]byte) bool {
		rand.Read(key[:])
		c := NewCipher(key[:])
		c.Encrypt(data, pt[:])
		c.Decrypt(data, data)
		return bytes.Equal(data, pt[:])
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestBulkBlocksEquivalence(t *testing.T) {
	key := append([]byte(nil), Key...)
	c := NewCipher(key)
	for _, size := range []int{0, BlockSize, 2 * BlockSize, 3 * BlockSize, 4 * BlockSize, 64 * BlockSize, 1024 * 1024} {
		src := make([]byte, size)
		for i := range src {
			src[i] = byte(19 + i*37)
		}

		wantEncrypted := make([]byte, size)
		for off := 0; off < size; off += BlockSize {
			c.Encrypt(wantEncrypted[off:off+BlockSize], src[off:off+BlockSize])
		}

		gotEncrypted := make([]byte, size)
		c.EncryptBlocks(gotEncrypted, src)
		if !bytes.Equal(gotEncrypted, wantEncrypted) {
			t.Fatalf("EncryptBlocks mismatch for %d bytes", size)
		}

		compactEncrypted := make([]byte, size)
		c.EncryptBlocksCompact(compactEncrypted, src)
		if !bytes.Equal(compactEncrypted, wantEncrypted) {
			t.Fatalf("EncryptBlocksCompact mismatch for %d bytes", size)
		}

		compactInPlace := append([]byte(nil), src...)
		c.EncryptBlocksCompact(compactInPlace, compactInPlace)
		if !bytes.Equal(compactInPlace, wantEncrypted) {
			t.Fatalf("EncryptBlocksCompact in-place mismatch for %d bytes", size)
		}

		inPlaceEncrypted := append([]byte(nil), src...)
		c.EncryptBlocks(inPlaceEncrypted, inPlaceEncrypted)
		if !bytes.Equal(inPlaceEncrypted, wantEncrypted) {
			t.Fatalf("EncryptBlocks in-place mismatch for %d bytes", size)
		}

		gotDecrypted := make([]byte, size)
		c.DecryptBlocks(gotDecrypted, wantEncrypted)
		if !bytes.Equal(gotDecrypted, src) {
			t.Fatalf("DecryptBlocks mismatch for %d bytes", size)
		}

		inPlaceDecrypted := append([]byte(nil), wantEncrypted...)
		c.DecryptBlocks(inPlaceDecrypted, inPlaceDecrypted)
		if !bytes.Equal(inPlaceDecrypted, src) {
			t.Fatalf("DecryptBlocks in-place mismatch for %d bytes", size)
		}
	}
}

func TestSetKeyEquivalentToNewCipher(t *testing.T) {
	firstKey := append([]byte(nil), Key...)
	secondKey := make([]byte, KeySize)
	for i := range secondKey {
		secondKey[i] = byte(i*29 + 7)
	}

	reused := NewCipher(firstKey)
	reused.SetKey(secondKey)
	fresh := NewCipher(secondKey)
	plaintext := make([]byte, 16*BlockSize)
	for i := range plaintext {
		plaintext[i] = byte(i*17 + 3)
	}

	reusedCiphertext := make([]byte, len(plaintext))
	freshCiphertext := make([]byte, len(plaintext))
	reused.EncryptBlocks(reusedCiphertext, plaintext)
	fresh.EncryptBlocks(freshCiphertext, plaintext)
	if !bytes.Equal(reusedCiphertext, freshCiphertext) {
		t.Fatal("SetKey encryption differs from a fresh cipher")
	}

	reusedPlaintext := make([]byte, len(plaintext))
	reused.DecryptBlocks(reusedPlaintext, reusedCiphertext)
	if !bytes.Equal(reusedPlaintext, plaintext) {
		t.Fatal("SetKey did not refresh decryption round keys")
	}

	reusedMAC := reused.SumGOST3413MAC(nil, plaintext, BlockSize)
	freshMAC := fresh.SumGOST3413MAC(nil, plaintext, BlockSize)
	if !bytes.Equal(reusedMAC, freshMAC) {
		t.Fatal("SetKey did not refresh MAC subkeys")
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

func BenchmarkBlockLatency(b *testing.B) {
	key := make([]byte, KeySize)
	copy(key, Key)
	c := NewCipher(key)

	b.Run("Encrypt/backend", func(b *testing.B) {
		blk := pt
		b.SetBytes(BlockSize)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			encryptBlock(&blk, &blk, &c.ks)
		}
		blockBenchSink = blk
	})

	b.Run("Decrypt/backend", func(b *testing.B) {
		blk := ct
		b.SetBytes(BlockSize)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			decryptBlock(&blk, &blk, &c.decKs)
		}
		blockBenchSink = blk
	})

	b.Run("Encrypt/cipher.Block", func(b *testing.B) {
		blk := append([]byte(nil), pt[:]...)
		b.SetBytes(BlockSize)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			c.Encrypt(blk, blk)
		}
		copy(blockBenchSink[:], blk)
	})

	b.Run("Decrypt/cipher.Block", func(b *testing.B) {
		blk := append([]byte(nil), ct[:]...)
		b.SetBytes(BlockSize)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			c.Decrypt(blk, blk)
		}
		copy(blockBenchSink[:], blk)
	})
}

func BenchmarkBlockThroughputIndependent(b *testing.B) {
	key := make([]byte, KeySize)
	copy(key, Key)
	c := NewCipher(key)

	b.Run("Encrypt8/backend", func(b *testing.B) {
		blocks := [8][BlockSize]byte{pt, pt, pt, pt, pt, pt, pt, pt}
		b.SetBytes(8 * BlockSize)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			encryptBlock(&blocks[0], &blocks[0], &c.ks)
			encryptBlock(&blocks[1], &blocks[1], &c.ks)
			encryptBlock(&blocks[2], &blocks[2], &c.ks)
			encryptBlock(&blocks[3], &blocks[3], &c.ks)
			encryptBlock(&blocks[4], &blocks[4], &c.ks)
			encryptBlock(&blocks[5], &blocks[5], &c.ks)
			encryptBlock(&blocks[6], &blocks[6], &c.ks)
			encryptBlock(&blocks[7], &blocks[7], &c.ks)
		}
		blockBenchSink = blocks[0]
	})

	b.Run("Decrypt8/backend", func(b *testing.B) {
		blocks := [8][BlockSize]byte{ct, ct, ct, ct, ct, ct, ct, ct}
		b.SetBytes(8 * BlockSize)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			decryptBlock(&blocks[0], &blocks[0], &c.decKs)
			decryptBlock(&blocks[1], &blocks[1], &c.decKs)
			decryptBlock(&blocks[2], &blocks[2], &c.decKs)
			decryptBlock(&blocks[3], &blocks[3], &c.decKs)
			decryptBlock(&blocks[4], &blocks[4], &c.decKs)
			decryptBlock(&blocks[5], &blocks[5], &c.decKs)
			decryptBlock(&blocks[6], &blocks[6], &c.decKs)
			decryptBlock(&blocks[7], &blocks[7], &c.decKs)
		}
		blockBenchSink = blocks[0]
	})
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

func BenchmarkEncryptOutOfPlace(b *testing.B) {
	key := make([]byte, KeySize)
	rand.Read(key)
	c := NewCipher(key)
	src := make([]byte, BlockSize)
	dst := make([]byte, BlockSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Encrypt(dst, src)
	}
}

func BenchmarkDecryptOutOfPlace(b *testing.B) {
	key := make([]byte, KeySize)
	rand.Read(key)
	c := NewCipher(key)
	src := make([]byte, BlockSize)
	dst := make([]byte, BlockSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Decrypt(dst, src)
	}
}

func BenchmarkNewCipher(b *testing.B) {
	key := make([]byte, KeySize)
	rand.Read(key)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = NewCipher(key)
	}
}

func BenchmarkKeySchedule(b *testing.B) {
	var key [KeySize]byte
	copy(key[:], Key)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = stretchKey(key)
	}
}

func BenchmarkDecryptRoundKeys(b *testing.B) {
	var key [KeySize]byte
	copy(key[:], Key)
	keys := stretchKey(key)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = decryptRoundKeys(keys)
	}
}

func TestS(t *testing.T) {
	blk := [BlockSize]byte{
		0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
	}
	s(&blk)
	if !bytes.Equal(blk[:], []byte{
		0xb6, 0x6c, 0xd8, 0x88, 0x7d, 0x38, 0xe8, 0xd7,
		0x77, 0x65, 0xae, 0xea, 0x0c, 0x9a, 0x7e, 0xfc,
	}) {
		t.FailNow()
	}
	s(&blk)
	if !bytes.Equal(blk[:], []byte{
		0x55, 0x9d, 0x8d, 0xd7, 0xbd, 0x06, 0xcb, 0xfe,
		0x7e, 0x7b, 0x26, 0x25, 0x23, 0x28, 0x0d, 0x39,
	}) {
		t.FailNow()
	}
	s(&blk)
	if !bytes.Equal(blk[:], []byte{
		0x0c, 0x33, 0x22, 0xfe, 0xd5, 0x31, 0xe4, 0x63,
		0x0d, 0x80, 0xef, 0x5c, 0x5a, 0x81, 0xc5, 0x0b,
	}) {
		t.FailNow()
	}
	s(&blk)
	if !bytes.Equal(blk[:], []byte{
		0x23, 0xae, 0x65, 0x63, 0x3f, 0x84, 0x2d, 0x29,
		0xc5, 0xdf, 0x52, 0x9c, 0x13, 0xf5, 0xac, 0xda,
	}) {
		t.FailNow()
	}
}

func R(blk []byte) {
	t := blk[15]
	for i := 0; i < 15; i++ {
		t ^= gfCache[blk[i]][lVector[i]]
	}
	copy(blk[1:], blk)
	blk[0] = t
}

func TestR(t *testing.T) {
	blk := [BlockSize]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
	}
	R(blk[:])
	if !bytes.Equal(blk[:], []byte{
		0x94, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}) {
		t.FailNow()
	}
	R(blk[:])
	if !bytes.Equal(blk[:], []byte{
		0xa5, 0x94, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}) {
		t.FailNow()
	}
	R(blk[:])
	if !bytes.Equal(blk[:], []byte{
		0x64, 0xa5, 0x94, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}) {
		t.FailNow()
	}
	R(blk[:])
	if !bytes.Equal(blk[:], []byte{
		0x0d, 0x64, 0xa5, 0x94, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}) {
		t.FailNow()
	}
}

func TestL(t *testing.T) {
	blk := [BlockSize]byte{
		0x64, 0xa5, 0x94, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	l(&blk)
	if !bytes.Equal(blk[:], []byte{
		0xd4, 0x56, 0x58, 0x4d, 0xd0, 0xe3, 0xe8, 0x4c,
		0xc3, 0x16, 0x6e, 0x4b, 0x7f, 0xa2, 0x89, 0x0d,
	}) {
		t.FailNow()
	}
	l(&blk)
	if !bytes.Equal(blk[:], []byte{
		0x79, 0xd2, 0x62, 0x21, 0xb8, 0x7b, 0x58, 0x4c,
		0xd4, 0x2f, 0xbc, 0x4f, 0xfe, 0xa5, 0xde, 0x9a,
	}) {
		t.FailNow()
	}
	l(&blk)
	if !bytes.Equal(blk[:], []byte{
		0x0e, 0x93, 0x69, 0x1a, 0x0c, 0xfc, 0x60, 0x40,
		0x8b, 0x7b, 0x68, 0xf6, 0x6b, 0x51, 0x3c, 0x13,
	}) {
		t.FailNow()
	}
	l(&blk)
	if !bytes.Equal(blk[:], []byte{
		0xe6, 0xa8, 0x09, 0x4f, 0xee, 0x0a, 0xa2, 0x04,
		0xfd, 0x97, 0xbc, 0xb0, 0xb4, 0x4b, 0x85, 0x80,
	}) {
		t.FailNow()
	}
}

func TestC(t *testing.T) {
	if !bytes.Equal(cBlk[0][:], []byte{
		0x6e, 0xa2, 0x76, 0x72, 0x6c, 0x48, 0x7a, 0xb8,
		0x5d, 0x27, 0xbd, 0x10, 0xdd, 0x84, 0x94, 0x01,
	}) {
		t.FailNow()
	}
	if !bytes.Equal(cBlk[1][:], []byte{
		0xdc, 0x87, 0xec, 0xe4, 0xd8, 0x90, 0xf4, 0xb3,
		0xba, 0x4e, 0xb9, 0x20, 0x79, 0xcb, 0xeb, 0x02,
	}) {
		t.FailNow()
	}
	if !bytes.Equal(cBlk[2][:], []byte{
		0xb2, 0x25, 0x9a, 0x96, 0xb4, 0xd8, 0x8e, 0x0b,
		0xe7, 0x69, 0x04, 0x30, 0xa4, 0x4f, 0x7f, 0x03,
	}) {
		t.FailNow()
	}
	if !bytes.Equal(cBlk[3][:], []byte{
		0x7b, 0xcd, 0x1b, 0x0b, 0x73, 0xe3, 0x2b, 0xa5,
		0xb7, 0x9c, 0xb1, 0x40, 0xf2, 0x55, 0x15, 0x04,
	}) {
		t.FailNow()
	}
	if !bytes.Equal(cBlk[4][:], []byte{
		0x15, 0x6f, 0x6d, 0x79, 0x1f, 0xab, 0x51, 0x1d,
		0xea, 0xbb, 0x0c, 0x50, 0x2f, 0xd1, 0x81, 0x05,
	}) {
		t.FailNow()
	}
	if !bytes.Equal(cBlk[5][:], []byte{
		0xa7, 0x4a, 0xf7, 0xef, 0xab, 0x73, 0xdf, 0x16,
		0x0d, 0xd2, 0x08, 0x60, 0x8b, 0x9e, 0xfe, 0x06,
	}) {
		t.FailNow()
	}
	if !bytes.Equal(cBlk[6][:], []byte{
		0xc9, 0xe8, 0x81, 0x9d, 0xc7, 0x3b, 0xa5, 0xae,
		0x50, 0xf5, 0xb5, 0x70, 0x56, 0x1a, 0x6a, 0x07,
	}) {
		t.FailNow()
	}
	if !bytes.Equal(cBlk[7][:], []byte{
		0xf6, 0x59, 0x36, 0x16, 0xe6, 0x05, 0x56, 0x89,
		0xad, 0xfb, 0xa1, 0x80, 0x27, 0xaa, 0x2a, 0x08,
	}) {
		t.FailNow()
	}
}

func TestRoundKeys(t *testing.T) {
	c := NewCipher(Key)
	if !bytes.Equal(c.ks[0][:], []byte{
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	}) {
		t.FailNow()
	}
	if !bytes.Equal(c.ks[1][:], []byte{
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	}) {
		t.FailNow()
	}
	if !bytes.Equal(c.ks[2][:], []byte{
		0xdb, 0x31, 0x48, 0x53, 0x15, 0x69, 0x43, 0x43,
		0x22, 0x8d, 0x6a, 0xef, 0x8c, 0xc7, 0x8c, 0x44,
	}) {
		t.FailNow()
	}
	if !bytes.Equal(c.ks[3][:], []byte{
		0x3d, 0x45, 0x53, 0xd8, 0xe9, 0xcf, 0xec, 0x68,
		0x15, 0xeb, 0xad, 0xc4, 0x0a, 0x9f, 0xfd, 0x04,
	}) {
		t.FailNow()
	}
	if !bytes.Equal(c.ks[4][:], []byte{
		0x57, 0x64, 0x64, 0x68, 0xc4, 0x4a, 0x5e, 0x28,
		0xd3, 0xe5, 0x92, 0x46, 0xf4, 0x29, 0xf1, 0xac,
	}) {
		t.FailNow()
	}
	if !bytes.Equal(c.ks[5][:], []byte{
		0xbd, 0x07, 0x94, 0x35, 0x16, 0x5c, 0x64, 0x32,
		0xb5, 0x32, 0xe8, 0x28, 0x34, 0xda, 0x58, 0x1b,
	}) {
		t.FailNow()
	}
	if !bytes.Equal(c.ks[6][:], []byte{
		0x51, 0xe6, 0x40, 0x75, 0x7e, 0x87, 0x45, 0xde,
		0x70, 0x57, 0x27, 0x26, 0x5a, 0x00, 0x98, 0xb1,
	}) {
		t.FailNow()
	}
	if !bytes.Equal(c.ks[7][:], []byte{
		0x5a, 0x79, 0x25, 0x01, 0x7b, 0x9f, 0xdd, 0x3e,
		0xd7, 0x2a, 0x91, 0xa2, 0x22, 0x86, 0xf9, 0x84,
	}) {
		t.FailNow()
	}
	if !bytes.Equal(c.ks[8][:], []byte{
		0xbb, 0x44, 0xe2, 0x53, 0x78, 0xc7, 0x31, 0x23,
		0xa5, 0xf3, 0x2f, 0x73, 0xcd, 0xb6, 0xe5, 0x17,
	}) {
		t.FailNow()
	}
	if !bytes.Equal(c.ks[9][:], []byte{
		0x72, 0xe9, 0xdd, 0x74, 0x16, 0xbc, 0xf4, 0x5b,
		0x75, 0x5d, 0xba, 0xa8, 0x8e, 0x4a, 0x40, 0x43,
	}) {
		t.FailNow()
	}
}

func TestVectorEncrypt(t *testing.T) {
	c := NewCipher(Key)
	dst := make([]byte, BlockSize)
	c.Encrypt(dst, pt[:])
	if !bytes.Equal(dst, ct[:]) {
		t.FailNow()
	}
}

func TestVectorDecrypt(t *testing.T) {
	c := NewCipher(Key)
	dst := make([]byte, BlockSize)
	c.Decrypt(dst, ct[:])
	if !bytes.Equal(dst, pt[:]) {
		t.FailNow()
	}
}

func TestCMRoundTrip(t *testing.T) {
	var key [KeySize]byte
	copy(key[:], Key)
	plaintext := []byte("gogost kuznechik counter mode round trip with a partial tail")

	ciphertext := CMXORKeyStream(nil, 0x0102030405060708, key, plaintext)
	if len(ciphertext) != len(plaintext) {
		t.Fatalf("unexpected ciphertext size: got %d, want %d", len(ciphertext), len(plaintext))
	}

	got := CMXORKeyStream(nil, 0x0102030405060708, key, ciphertext)
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("counter mode round trip mismatch")
	}
}

func TestCMXORKeyStreamAppendAndInPlace(t *testing.T) {
	var key [KeySize]byte
	copy(key[:], Key)
	plaintext := []byte("gogost kuznechik counter mode append and in-place")
	want := CMXORKeyStream(nil, 0x0102030405060708, key, plaintext)

	dst := []byte{0xaa, 0xbb, 0xcc}
	out := CMXORKeyStream(dst, 0x0102030405060708, key, plaintext)
	if !bytes.Equal(out[:len(dst)], dst) {
		t.Fatalf("prefix was overwritten")
	}
	if !bytes.Equal(out[len(dst):], want) {
		t.Fatalf("append output mismatch")
	}

	inPlace := append([]byte(nil), plaintext...)
	out = CMXORKeyStream(inPlace[:0], 0x0102030405060708, key, inPlace)
	if len(out) != len(inPlace) || &out[0] != &inPlace[0] {
		t.Fatalf("in-place output did not reuse the input buffer")
	}
	if !bytes.Equal(out, want) {
		t.Fatalf("in-place output mismatch")
	}

	prealloc := make([]byte, 0, len(plaintext))
	initCipherTables()
	allocs := testing.AllocsPerRun(100, func() {
		out := CMXORKeyStream(prealloc[:0], 0x0102030405060708, key, plaintext)
		if len(out) != len(plaintext) {
			t.Fatalf("unexpected output size")
		}
	})
	if allocs != 0 {
		t.Fatalf("preallocated CMXORKeyStream allocs = %v, want 0", allocs)
	}
}

func BenchmarkCMXORKeyStream1KiBAlloc(b *testing.B) {
	var key [KeySize]byte
	copy(key[:], Key)
	plaintext := make([]byte, 1024)
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = CMXORKeyStream(nil, uint64(i), key, plaintext)
	}
}

func BenchmarkCMXORKeyStream(b *testing.B) {
	var key [KeySize]byte
	copy(key[:], Key)
	sizes := []struct {
		name string
		size int
	}{
		{"16B", 16},
		{"64B", 64},
		{"1KiB", 1024},
		{"4KiB", 4 * 1024},
		{"16KiB", 16 * 1024},
		{"64KiB", 64 * 1024},
		{"1MiB", 1024 * 1024},
	}

	for _, size := range sizes {
		plaintext := make([]byte, size.size)
		b.Run(size.name+"/prealloc", func(b *testing.B) {
			dst := make([]byte, 0, len(plaintext))
			b.SetBytes(int64(len(plaintext)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				out := CMXORKeyStream(dst[:0], uint64(i), key, plaintext)
				if len(out) != len(plaintext) {
					b.Fatal("unexpected output size")
				}
			}
		})
		b.Run(size.name+"/alloc", func(b *testing.B) {
			b.SetBytes(int64(len(plaintext)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				out := CMXORKeyStream(nil, uint64(i), key, plaintext)
				if len(out) != len(plaintext) {
					b.Fatal("unexpected output size")
				}
			}
		})
		b.Run(size.name+"/inplace", func(b *testing.B) {
			buf := make([]byte, len(plaintext))
			b.SetBytes(int64(len(plaintext)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				out := CMXORKeyStream(buf[:0], uint64(i), key, buf)
				if len(out) != len(buf) {
					b.Fatal("unexpected output size")
				}
			}
		})
	}
}

func BenchmarkCTR(b *testing.B) {
	key := make([]byte, KeySize)
	copy(key, Key)
	iv := make([]byte, BlockSize)
	sizes := []struct {
		name string
		size int
	}{
		{"16B", 16},
		{"64B", 64},
		{"1KiB", 1024},
		{"4KiB", 4 * 1024},
		{"16KiB", 16 * 1024},
		{"64KiB", 64 * 1024},
		{"1MiB", 1024 * 1024},
	}

	for _, size := range sizes {
		src := make([]byte, size.size)
		dst := make([]byte, size.size)
		b.Run(size.name, func(b *testing.B) {
			block := NewCipher(key)
			stream := cipher.NewCTR(block, iv)
			b.SetBytes(int64(len(src)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				stream.XORKeyStream(dst, src)
			}
		})
	}
}

func BenchmarkStandardModes(b *testing.B) {
	key := make([]byte, KeySize)
	copy(key, Key)
	iv := make([]byte, BlockSize)
	sizes := []struct {
		name string
		size int
	}{
		{"16B", 16},
		{"64B", 64},
		{"1KiB", 1024},
		{"4KiB", 4 * 1024},
		{"16KiB", 16 * 1024},
		{"64KiB", 64 * 1024},
		{"1MiB", 1024 * 1024},
	}

	for _, size := range sizes {
		src := make([]byte, size.size)
		dst := make([]byte, size.size)
		b.Run(size.name+"/CBCEncrypt", func(b *testing.B) {
			block := NewCipher(key)
			mode := cipher.NewCBCEncrypter(block, iv)
			b.SetBytes(int64(len(src)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				mode.CryptBlocks(dst, src)
			}
		})
		b.Run(size.name+"/CBCDecrypt", func(b *testing.B) {
			block := NewCipher(key)
			mode := cipher.NewCBCDecrypter(block, iv)
			b.SetBytes(int64(len(src)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				mode.CryptBlocks(dst, src)
			}
		})
		b.Run(size.name+"/CFBEncrypt", func(b *testing.B) {
			block := NewCipher(key)
			stream := cipher.NewCFBEncrypter(block, iv)
			b.SetBytes(int64(len(src)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				stream.XORKeyStream(dst, src)
			}
		})
		b.Run(size.name+"/CFBDecrypt", func(b *testing.B) {
			block := NewCipher(key)
			stream := cipher.NewCFBDecrypter(block, iv)
			b.SetBytes(int64(len(src)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				stream.XORKeyStream(dst, src)
			}
		})
		b.Run(size.name+"/OFB", func(b *testing.B) {
			block := NewCipher(key)
			stream := cipher.NewOFB(block, iv)
			b.SetBytes(int64(len(src)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				stream.XORKeyStream(dst, src)
			}
		})
	}
}
