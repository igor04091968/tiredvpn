package gost34112012256

import "testing"

var (
	benchKDFOut    []byte
	bench256Digest []byte
)

func bench256Data(n int) []byte {
	data := make([]byte, n)
	for i := range data {
		data[i] = byte(i*31 + 17)
	}
	return data
}

func BenchmarkHashMatrix(b *testing.B) {
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
		data := bench256Data(size.n)
		h := New()
		b.Run(size.name, func(b *testing.B) {
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				h.Reset()
				if _, err := h.Write(data); err != nil {
					b.Fatal(err)
				}
				bench256Digest = h.Sum(bench256Digest[:0])
			}
		})
	}
}

func BenchmarkKDF(b *testing.B) {
	key := make([]byte, Size)
	label := []byte("benchmark label")
	seed := []byte("benchmark seed")
	for i := range key {
		key[i] = byte(i*11 + 1)
	}
	kdf := NewKDF(key)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchKDFOut = kdf.Derive(benchKDFOut[:0], label, seed)
	}
}

func BenchmarkTLSTree(b *testing.B) {
	keyRoot := make([]byte, Size)
	for i := range keyRoot {
		keyRoot[i] = byte(i*7 + 3)
	}
	tree := NewTLSTree(TLSGOSTR341112256WithKuznyechikMGMS, keyRoot)
	b.Run("cached", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			benchKDFOut, _ = tree.DeriveCached(128)
		}
	})
	b.Run("derive", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			benchKDFOut = tree.Derive(uint64(i + 1))
		}
	})
	b.Run("derive_into", func(b *testing.B) {
		dst := make([]byte, 0, Size)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			benchKDFOut = tree.DeriveInto(dst[:0], uint64(i+1))
		}
	})
}
