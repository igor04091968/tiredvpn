//go:build amd64 && !purego

package gost341264

import (
	"bytes"
	"testing"
	"unsafe"
)

func TestAVX2BlocksEquivalent(t *testing.T) {
	if !useAVX2 {
		t.Skip("AVX2 is not available")
	}
	testSIMDBlocksEquivalent(t, "AVX2", func(dst, src []byte, c *Cipher, keys *[32]word) {
		cryptBlocksAVX2(unsafe.Pointer(&dst[0]), unsafe.Pointer(&src[0]), uintptr(len(src)), keys)
	})
	testSIMDBlocksEquivalent(t, "AVX2x16", func(dst, src []byte, c *Cipher, keys *[32]word) {
		cryptBlocksAVX2x16(unsafe.Pointer(&dst[0]), unsafe.Pointer(&src[0]), uintptr(len(src)), keys)
	})
}

func testSIMDBlocksEquivalent(t *testing.T, name string, fn func(dst, src []byte, c *Cipher, keys *[32]word)) {
	t.Helper()
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i*19 + 7)
	}
	c := NewCipher(key)
	src := make([]byte, 16*BlockSize)
	for i := range src {
		src[i] = byte(i*29 + 5)
	}
	want := make([]byte, len(src))
	for off := 0; off < len(src); off += BlockSize {
		c.Encrypt(want[off:off+BlockSize], src[off:off+BlockSize])
	}
	got := make([]byte, len(src))
	fn(got, src, c, &c.encKeys)
	if !bytes.Equal(got, want) {
		t.Fatalf("%s encrypt mismatch\nwant %x\ngot  %x", name, want[:BlockSize], got[:BlockSize])
	}
	plain := make([]byte, len(src))
	fn(plain, got, c, &c.decKeys)
	if !bytes.Equal(plain, src) {
		t.Fatalf("%s decrypt mismatch\nwant %x\ngot  %x", name, src[:BlockSize], plain[:BlockSize])
	}
}

func BenchmarkSIMDBackends(b *testing.B) {
	c := NewCipher(benchMagmaKey())
	for _, size := range []struct {
		name string
		n    int
	}{
		{"64B", 64},
		{"128B", 128},
		{"1KiB", 1024},
		{"16KiB", 16 * 1024},
		{"1MiB", 1 << 20},
		{"16MiB", 16 << 20},
	} {
		src := benchMagmaData(size.n)
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
			copy(benchMagmaOut[:], dst)
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
			copy(benchMagmaOut[:], dst)
		})
		b.Run("AVX2Encrypt/"+size.name, func(b *testing.B) {
			if !useAVX2 {
				b.Skip("AVX2 backend is not available")
			}
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				cryptBlocksAVX2(unsafe.Pointer(&dst[0]), unsafe.Pointer(&src[0]), uintptr(len(src)), &c.encKeys)
			}
			copy(benchMagmaOut[:], dst)
		})
		b.Run("AVX2Decrypt/"+size.name, func(b *testing.B) {
			if !useAVX2 {
				b.Skip("AVX2 backend is not available")
			}
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				cryptBlocksAVX2(unsafe.Pointer(&dst[0]), unsafe.Pointer(&encrypted[0]), uintptr(len(encrypted)), &c.decKeys)
			}
			copy(benchMagmaOut[:], dst)
		})
		if size.n >= 16*BlockSize {
			b.Run("AVX2x16Encrypt/"+size.name, func(b *testing.B) {
				if !useAVX2 {
					b.Skip("AVX2 backend is not available")
				}
				n := len(src) &^ (16*BlockSize - 1)
				b.SetBytes(int64(n))
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					cryptBlocksAVX2x16(unsafe.Pointer(&dst[0]), unsafe.Pointer(&src[0]), uintptr(n), &c.encKeys)
				}
				copy(benchMagmaOut[:], dst[:n])
			})
			b.Run("AVX2x16Decrypt/"+size.name, func(b *testing.B) {
				if !useAVX2 {
					b.Skip("AVX2 backend is not available")
				}
				n := len(encrypted) &^ (16*BlockSize - 1)
				b.SetBytes(int64(n))
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					cryptBlocksAVX2x16(unsafe.Pointer(&dst[0]), unsafe.Pointer(&encrypted[0]), uintptr(n), &c.decKeys)
				}
				copy(benchMagmaOut[:], dst[:n])
			})
		}
	}
}
