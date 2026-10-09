package gost28147

import "testing"

var (
	bench28147Block [BlockSize]byte
	bench28147Out   [1 << 20]byte
	bench28147Bool  bool
)

func bench28147Key() []byte {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i*17 + 3)
	}
	return key
}

func bench28147Data(n int) []byte {
	data := make([]byte, n)
	for i := range data {
		data[i] = byte(i*31 + 11)
	}
	return data
}

func BenchmarkNewCipher(b *testing.B) {
	key := bench28147Key()
	b.Run("Pointer", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if NewCipher(key, &SboxIdGost2814789CryptoProAParamSet) == nil {
				b.Fatal("nil cipher")
			}
		}
	})
	b.Run("Value", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = NewCipherValue(key, &SboxIdGost2814789CryptoProAParamSet)
		}
	})
	b.Run("SetKey", func(b *testing.B) {
		var c Cipher
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			c.SetKey(key, &SboxIdGost2814789CryptoProAParamSet)
		}
	})
}

func BenchmarkBlock(b *testing.B) {
	c := NewCipher(bench28147Key(), &SboxIdGost2814789CryptoProAParamSet)
	var src, dst [BlockSize]byte
	for i := range src {
		src[i] = byte(i)
	}
	b.Run("Encrypt", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			c.Encrypt(dst[:], src[:])
		}
		bench28147Block = dst
	})
	b.Run("EncryptInPlace", func(b *testing.B) {
		block := src
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			c.Encrypt(block[:], block[:])
		}
		bench28147Block = block
	})
	b.Run("Decrypt", func(b *testing.B) {
		c.Encrypt(src[:], src[:])
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			c.Decrypt(dst[:], src[:])
		}
		bench28147Block = dst
	})
	b.Run("DecryptInPlace", func(b *testing.B) {
		block := src
		c.Encrypt(block[:], block[:])
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			c.Decrypt(block[:], block[:])
		}
		bench28147Block = block
	})
}

func BenchmarkBulkBlocks(b *testing.B) {
	c := NewCipher(bench28147Key(), &SboxIdGost2814789CryptoProAParamSet)
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
		{"1KiB", 1024},
		{"16KiB", 16 * 1024},
		{"1MiB", 1 << 20},
	} {
		src := bench28147Data(size.n)
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
			copy(bench28147Out[:], dst)
		})
		b.Run("EncryptBlocks/"+size.name, func(b *testing.B) {
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				c.EncryptBlocks(dst, src)
			}
			copy(bench28147Out[:], dst)
		})
		b.Run("DecryptBlocks/"+size.name, func(b *testing.B) {
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				c.DecryptBlocks(dst, encrypted)
			}
			copy(bench28147Out[:], dst)
		})
		b.Run("EncryptBlocksInPlace/"+size.name, func(b *testing.B) {
			buf := append([]byte(nil), src...)
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				c.EncryptBlocks(buf, buf)
			}
			copy(bench28147Out[:], buf)
		})
	}
}

func BenchmarkCTRMatrix(b *testing.B) {
	c := NewCipher(bench28147Key(), &SboxIdGost2814789CryptoProAParamSet)
	iv := bench28147Data(BlockSize)
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
		src := bench28147Data(size.n)
		dst := make([]byte, size.n)
		b.Run("NewCTR/"+size.name, func(b *testing.B) {
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				c.NewCTR(iv).XORKeyStream(dst, src)
			}
			copy(bench28147Out[:], dst)
		})
		b.Run("NewCTRValue/"+size.name, func(b *testing.B) {
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				ctr := c.NewCTRValue(iv)
				ctr.XORKeyStream(dst, src)
			}
			copy(bench28147Out[:], dst)
		})
		b.Run("OneShot/"+size.name, func(b *testing.B) {
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				c.XORKeyStreamCTR(dst, src, iv)
			}
			copy(bench28147Out[:], dst)
		})
	}
}

func BenchmarkMACMatrix(b *testing.B) {
	c := NewCipher(bench28147Key(), &SboxIdGost2814789CryptoProAParamSet)
	iv := bench28147Data(BlockSize)
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
		src := bench28147Data(size.n)
		b.Run("NewMAC/"+size.name, func(b *testing.B) {
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				mac, err := c.NewMAC(BlockSize, iv)
				if err != nil {
					b.Fatal(err)
				}
				if _, err = mac.Write(src); err != nil {
					b.Fatal(err)
				}
				bench28147Bool = len(mac.Sum(nil)) == BlockSize
			}
		})
		b.Run("NewMACValue/"+size.name, func(b *testing.B) {
			dst := make([]byte, 0, BlockSize)
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				mac, err := c.NewMACValue(BlockSize, iv)
				if err != nil {
					b.Fatal(err)
				}
				if _, err = mac.Write(src); err != nil {
					b.Fatal(err)
				}
				bench28147Bool = len(mac.Sum(dst[:0])) == BlockSize
			}
		})
		b.Run("SumMAC/"+size.name, func(b *testing.B) {
			dst := make([]byte, 0, BlockSize)
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				tag, err := c.SumMAC(dst[:0], src, BlockSize, iv)
				if err != nil {
					b.Fatal(err)
				}
				bench28147Bool = len(tag) == BlockSize
			}
		})
	}
}
