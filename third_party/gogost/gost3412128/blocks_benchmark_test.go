package gost3412128

import "testing"

var benchKuznechikBlocksOut [1 << 20]byte

func BenchmarkBulkBlocks(b *testing.B) {
	key := make([]byte, KeySize)
	copy(key, Key)
	c := NewCipher(key)
	for _, size := range []struct {
		name string
		n    int
	}{
		{"16B", 16},
		{"32B", 32},
		{"64B", 64},
		{"128B", 128},
		{"1KiB", 1024},
		{"16KiB", 16 * 1024},
		{"1MiB", 1 << 20},
		{"16MiB", 16 << 20},
	} {
		src := make([]byte, size.n)
		for i := range src {
			src[i] = byte(i*31 + 17)
		}
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
			copy(benchKuznechikBlocksOut[:], dst)
		})
		b.Run("EncryptBlocks/"+size.name, func(b *testing.B) {
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				c.EncryptBlocks(dst, src)
			}
			copy(benchKuznechikBlocksOut[:], dst)
		})
		b.Run("DecryptBlocks/"+size.name, func(b *testing.B) {
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				c.DecryptBlocks(dst, encrypted)
			}
			copy(benchKuznechikBlocksOut[:], dst)
		})
	}
}

func BenchmarkCTRCounter(b *testing.B) {
	key := make([]byte, KeySize)
	copy(key, Key)
	c := NewCipher(key)
	for _, size := range []struct {
		name string
		n    int
	}{
		{"8B", 8},
		{"16B", 16},
		{"32B", 32},
		{"64B", 64},
		{"1KiB", 1024},
		{"16KiB", 16 * 1024},
		{"1MiB", 1 << 20},
	} {
		src := make([]byte, size.n)
		for i := range src {
			src[i] = byte(i*31 + 17)
		}
		dst := make([]byte, size.n)
		b.Run(size.name, func(b *testing.B) {
			var counter [BlockSize]byte
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				counter[0] = byte(i)
				counter[1] = byte(i >> 8)
				c.XORKeyStreamCTRCounter(dst, src, counter[:])
			}
			copy(benchKuznechikBlocksOut[:], dst)
		})
	}
}
