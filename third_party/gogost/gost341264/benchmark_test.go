package gost341264

import (
	"crypto/cipher"
	"testing"
)

var (
	benchMagmaBlock [BlockSize]byte
	benchMagmaOut   [1 << 20]byte
)

func benchMagmaKey() []byte {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i*19 + 7)
	}
	return key
}

func benchMagmaData(n int) []byte {
	data := make([]byte, n)
	for i := range data {
		data[i] = byte(i*29 + 5)
	}
	return data
}

func BenchmarkNewCipher(b *testing.B) {
	key := benchMagmaKey()
	b.Run("Pointer", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if NewCipher(key) == nil {
				b.Fatal("nil cipher")
			}
		}
	})
	b.Run("Value", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = NewCipherValue(key)
		}
	})
	b.Run("SetKey", func(b *testing.B) {
		var c Cipher
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			c.SetKey(key)
		}
	})
}

func BenchmarkBlock(b *testing.B) {
	c := NewCipher(benchMagmaKey())
	var src, dst [BlockSize]byte
	for i := range src {
		src[i] = byte(i)
	}
	b.Run("Encrypt", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			c.Encrypt(dst[:], src[:])
		}
		benchMagmaBlock = dst
	})
	b.Run("EncryptInPlace", func(b *testing.B) {
		block := src
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			c.Encrypt(block[:], block[:])
		}
		benchMagmaBlock = block
	})
	b.Run("Decrypt", func(b *testing.B) {
		c.Encrypt(src[:], src[:])
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			c.Decrypt(dst[:], src[:])
		}
		benchMagmaBlock = dst
	})
	b.Run("DecryptInPlace", func(b *testing.B) {
		block := src
		c.Encrypt(block[:], block[:])
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			c.Decrypt(block[:], block[:])
		}
		benchMagmaBlock = block
	})
}

func BenchmarkBulkBlocks(b *testing.B) {
	c := NewCipher(benchMagmaKey())
	for _, size := range []struct {
		name string
		n    int
	}{
		{"8B", 8},
		{"16B", 16},
		{"24B", 24},
		{"32B", 32},
		{"40B", 40},
		{"48B", 48},
		{"56B", 56},
		{"64B", 64},
		{"72B", 72},
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
		b.Run("LoopEncrypt/"+size.name, func(b *testing.B) {
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				for off := 0; off < len(src); off += BlockSize {
					c.Encrypt(dst[off:off+BlockSize], src[off:off+BlockSize])
				}
			}
			copy(benchMagmaOut[:], dst)
		})
		b.Run("EncryptBlocks/"+size.name, func(b *testing.B) {
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				c.EncryptBlocks(dst, src)
			}
			copy(benchMagmaOut[:], dst)
		})
		b.Run("DecryptBlocks/"+size.name, func(b *testing.B) {
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				c.DecryptBlocks(dst, encrypted)
			}
			copy(benchMagmaOut[:], dst)
		})
		b.Run("EncryptBlocksInPlace/"+size.name, func(b *testing.B) {
			buf := append([]byte(nil), src...)
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				c.EncryptBlocks(buf, buf)
			}
			copy(benchMagmaOut[:], buf)
		})
	}
}

func BenchmarkCTR(b *testing.B) {
	c := NewCipher(benchMagmaKey())
	iv := benchMagmaData(BlockSize)
	for _, size := range []struct {
		name string
		n    int
	}{
		{"16B", 16},
		{"64B", 64},
		{"1KiB", 1024},
		{"16KiB", 16 * 1024},
		{"1MiB", 1 << 20},
	} {
		src := benchMagmaData(size.n)
		dst := make([]byte, size.n)
		b.Run("cipher.NewCTR/"+size.name, func(b *testing.B) {
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				cipher.NewCTR(c, iv).XORKeyStream(dst, src)
			}
			copy(benchMagmaOut[:], dst)
		})
		b.Run("XORKeyStreamCTR/"+size.name, func(b *testing.B) {
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				c.XORKeyStreamCTR(dst, src, iv)
			}
			copy(benchMagmaOut[:], dst)
		})
		b.Run("XORKeyStreamCTRInPlace/"+size.name, func(b *testing.B) {
			buf := append([]byte(nil), src...)
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				c.XORKeyStreamCTR(buf, buf, iv)
			}
			copy(benchMagmaOut[:], buf)
		})
	}
}
