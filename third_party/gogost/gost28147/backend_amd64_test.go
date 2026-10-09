//go:build amd64 && !purego

package gost28147

import (
	"bytes"
	"testing"
	"unsafe"
)

func TestAVX2BlocksEquivalent(t *testing.T) {
	if !useAVX2 {
		t.Skip("AVX2 is not available")
	}
	testSIMDBlocksEquivalent(t, "AVX2", func(dst, src []byte, c *Cipher, keys *[32]nv) {
		cryptBlocksAVX2(unsafe.Pointer(&dst[0]), unsafe.Pointer(&src[0]), uintptr(len(src)), keys, &c.simdSbox)
	})
}

func TestAVX2CTREquivalent(t *testing.T) {
	if !useAVX2 {
		t.Skip("AVX2 is not available")
	}
	key := make([]byte, KeySize)
	iv := make([]byte, BlockSize)
	for i := range key {
		key[i] = byte(i*17 + 3)
	}
	for i := range iv {
		iv[i] = byte(i*11 + 5)
	}
	for _, size := range []int{1024, 2048, 4096, 4096 + 13} {
		src := make([]byte, size)
		for i := range src {
			src[i] = byte(i*31 + 11)
		}
		c := NewCipher(key, SboxDefault)
		want := make([]byte, len(src))
		oldAVX2 := useAVX2
		useAVX2 = false
		c.XORKeyStreamCTR(want, src, iv)
		useAVX2 = oldAVX2

		got := make([]byte, len(src))
		c.XORKeyStreamCTR(got, src, iv)
		if !bytes.Equal(got, want) {
			t.Fatalf("AVX2 CTR mismatch for %d bytes\nwant %x\ngot  %x", size, want[:min(len(want), 32)], got[:min(len(got), 32)])
		}
	}

	src := make([]byte, 1024)
	for i := range src {
		src[i] = byte(i*13 + 7)
	}
	c := NewCipher(key, SboxDefault)
	want := make([]byte, len(src))
	oldAVX2 := useAVX2
	useAVX2 = false
	scalar := CTR{c: c, n1: 0x11223344, n2: 0xffffffff - 0x01010104}
	scalar.XORKeyStream(want, src)
	useAVX2 = oldAVX2

	got := make([]byte, len(src))
	direct := CTR{c: c, n1: 0x11223344, n2: 0xffffffff - 0x01010104}
	direct.XORKeyStream(got, src)
	if !bytes.Equal(got, want) {
		t.Fatalf("AVX2 CTR wrap mismatch\nwant %x\ngot  %x", want[:32], got[:32])
	}
}

func testSIMDBlocksEquivalent(t *testing.T, name string, fn func(dst, src []byte, c *Cipher, keys *[32]nv)) {
	t.Helper()
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i*17 + 3)
	}
	for _, sbox := range []*Sbox{
		&SboxIdGost2814789TestParamSet,
		&SboxIdGost2814789CryptoProAParamSet,
	} {
		c := NewCipher(key, sbox)
		src := make([]byte, 8*BlockSize)
		for i := range src {
			src[i] = byte(i*31 + 11)
		}
		want := make([]byte, len(src))
		for off := 0; off < len(src); off += BlockSize {
			c.Encrypt(want[off:off+BlockSize], src[off:off+BlockSize])
		}
		got := make([]byte, len(src))
		fn(got, src, c, &c.encKeys)
		if !bytes.Equal(got, want) {
			t.Fatalf("%s encrypt mismatch for sbox %p\nwant %x\ngot  %x", name, sbox, want[:BlockSize], got[:BlockSize])
		}
		plain := make([]byte, len(src))
		fn(plain, got, c, &c.decKeys)
		if !bytes.Equal(plain, src) {
			t.Fatalf("%s decrypt mismatch for sbox %p\nwant %x\ngot  %x", name, sbox, src[:BlockSize], plain[:BlockSize])
		}
	}
}

func BenchmarkSIMDBackends(b *testing.B) {
	key := bench28147Key()
	c := NewCipher(key, &SboxIdGost2814789CryptoProAParamSet)
	for _, size := range []struct {
		name string
		n    int
	}{
		{"64B", 64},
		{"1KiB", 1024},
		{"16KiB", 16 * 1024},
		{"1MiB", 1 << 20},
	} {
		src := bench28147Data(size.n)
		dst := make([]byte, size.n)
		encrypted := make([]byte, size.n)
		c.EncryptBlocks(encrypted, src)

		b.Run("GoEncrypt/"+size.name, func(b *testing.B) {
			oldAVX2 := useAVX2
			useAVX2 = false
			b.Cleanup(func() {
				useAVX2 = oldAVX2
			})
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				c.EncryptBlocks(dst, src)
			}
			copy(bench28147Out[:], dst)
		})
		b.Run("GoDecrypt/"+size.name, func(b *testing.B) {
			oldAVX2 := useAVX2
			useAVX2 = false
			b.Cleanup(func() {
				useAVX2 = oldAVX2
			})
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				c.DecryptBlocks(dst, encrypted)
			}
			copy(bench28147Out[:], dst)
		})
		b.Run("AVX2Encrypt/"+size.name, func(b *testing.B) {
			if !useAVX2 {
				b.Skip("AVX2 backend is not available")
			}
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				cryptBlocksAVX2(unsafe.Pointer(&dst[0]), unsafe.Pointer(&src[0]), uintptr(len(src)), &c.encKeys, &c.simdSbox)
			}
			copy(bench28147Out[:], dst)
		})
		b.Run("AVX2Decrypt/"+size.name, func(b *testing.B) {
			if !useAVX2 {
				b.Skip("AVX2 backend is not available")
			}
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				cryptBlocksAVX2(unsafe.Pointer(&dst[0]), unsafe.Pointer(&encrypted[0]), uintptr(len(encrypted)), &c.decKeys, &c.simdSbox)
			}
			copy(bench28147Out[:], dst)
		})
	}
}

func BenchmarkCTRBackends(b *testing.B) {
	if !useAVX2 {
		b.Skip("AVX2 backend is not available")
	}
	key := bench28147Key()
	c := NewCipher(key, &SboxIdGost2814789CryptoProAParamSet)
	for _, size := range []struct {
		name string
		n    int
	}{
		{"1KiB", 1024},
		{"16KiB", 16 * 1024},
		{"1MiB", 1 << 20},
	} {
		src := bench28147Data(size.n)
		dst := make([]byte, size.n)
		b.Run("Buffered/"+size.name, func(b *testing.B) {
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				ctr := CTR{c: c, n1: 1, n2: 0}
				xorKeyStreamCTRBufferedAVX2(&ctr, dst, src)
			}
			copy(bench28147Out[:], dst)
		})
	}
}
