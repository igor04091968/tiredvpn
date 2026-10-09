package mgm

import (
	"crypto/rand"
	"testing"

	"gitverse.ru/uzer_007/gogost/v3/gost3412128"
	"gitverse.ru/uzer_007/gogost/v3/gost341264"
)

func BenchmarkMulAdd(b *testing.B) {
	b.Run("64", func(b *testing.B) {
		var sum, x, y [8]byte
		rand.Read(sum[:])
		rand.Read(x[:])
		rand.Read(y[:])
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			mulAdd64(sum[:], x[:], y[:])
		}
	})
	b.Run("128", func(b *testing.B) {
		var sum, x, y [16]byte
		rand.Read(sum[:])
		rand.Read(x[:])
		rand.Read(y[:])
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			mulAdd128(sum[:], x[:], y[:])
		}
	})
}

func BenchmarkMGM64Sizes(b *testing.B) {
	key := make([]byte, gost341264.KeySize)
	rand.Read(key)
	nonce := make([]byte, gost341264.BlockSize)
	rand.Read(nonce)
	nonce[0] &= 0x7F
	c := gost341264.NewCipher(key)
	aead, err := NewMGM(c, gost341264.BlockSize)
	if err != nil {
		panic(err)
	}
	for _, size := range []struct {
		name string
		size int
	}{
		{"16B", 16},
		{"64B", 64},
		{"1KiB", 1024},
		{"16KiB", 16 * 1024},
	} {
		pt := make([]byte, size.size)
		rand.Read(pt)
		ct := make([]byte, len(pt)+aead.Overhead())
		sealed := aead.Seal(nil, nonce, pt, nil)
		b.Run(size.name+"/seal", func(b *testing.B) {
			b.SetBytes(int64(len(pt)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				aead.Seal(ct[:0], nonce, pt, nil)
			}
		})
		b.Run(size.name+"/open", func(b *testing.B) {
			dst := make([]byte, 0, len(pt))
			b.SetBytes(int64(len(pt)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				out, err := aead.Open(dst[:0], nonce, sealed, nil)
				if err != nil || len(out) != len(pt) {
					b.Fatal("unexpected open result")
				}
			}
		})
	}
}

func BenchmarkMGM128AssociatedData(b *testing.B) {
	key := make([]byte, gost3412128.KeySize)
	rand.Read(key)
	nonce := make([]byte, gost3412128.BlockSize)
	rand.Read(nonce)
	nonce[0] &= 0x7F
	pt := make([]byte, 1024)
	ad := make([]byte, 1024)
	rand.Read(pt)
	rand.Read(ad)
	c := gost3412128.NewCipher(key)
	aead, err := NewMGM(c, gost3412128.BlockSize)
	if err != nil {
		panic(err)
	}
	ct := make([]byte, len(pt)+aead.Overhead())
	b.SetBytes(int64(len(pt) + len(ad)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		aead.Seal(ct[:0], nonce, pt, ad)
	}
}
