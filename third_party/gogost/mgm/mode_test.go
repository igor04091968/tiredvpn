package mgm

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"testing"
	"testing/quick"

	"gitverse.ru/uzer_007/gogost/v3/gost3412128"
	"gitverse.ru/uzer_007/gogost/v3/gost341264"
)

type genericBlock struct {
	cipher.Block
}

func TestVector(t *testing.T) {
	key := []byte{
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
	}
	additionalData := []byte{
		0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
		0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
		0xEA, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
		0x05,
	}
	plaintext := []byte{
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
		0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xEE, 0xFF, 0x0A,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xAA, 0xBB, 0xCC, 0xEE, 0xFF, 0x0A, 0x00,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
		0xAA, 0xBB, 0xCC, 0xEE, 0xFF, 0x0A, 0x00, 0x11,
		0xAA, 0xBB, 0xCC,
	}
	c := gost3412128.NewCipher(key)
	nonce := plaintext[:16]
	aead, _ := NewMGM(c, 16)
	sealed := aead.Seal(nil, nonce, plaintext, additionalData)
	if !bytes.Equal(sealed[:len(plaintext)], []byte{
		0xA9, 0x75, 0x7B, 0x81, 0x47, 0x95, 0x6E, 0x90,
		0x55, 0xB8, 0xA3, 0x3D, 0xE8, 0x9F, 0x42, 0xFC,
		0x80, 0x75, 0xD2, 0x21, 0x2B, 0xF9, 0xFD, 0x5B,
		0xD3, 0xF7, 0x06, 0x9A, 0xAD, 0xC1, 0x6B, 0x39,
		0x49, 0x7A, 0xB1, 0x59, 0x15, 0xA6, 0xBA, 0x85,
		0x93, 0x6B, 0x5D, 0x0E, 0xA9, 0xF6, 0x85, 0x1C,
		0xC6, 0x0C, 0x14, 0xD4, 0xD3, 0xF8, 0x83, 0xD0,
		0xAB, 0x94, 0x42, 0x06, 0x95, 0xC7, 0x6D, 0xEB,
		0x2C, 0x75, 0x52,
	}) {
		t.FailNow()
	}
	if !bytes.Equal(sealed[len(plaintext):], []byte{
		0xCF, 0x5D, 0x65, 0x6F, 0x40, 0xC3, 0x4F, 0x5C,
		0x46, 0xE8, 0xBB, 0x0E, 0x29, 0xFC, 0xDB, 0x4C,
	}) {
		t.FailNow()
	}
	_, err := aead.Open(sealed[:0], nonce, sealed, additionalData)
	if err != nil {
		t.FailNow()
	}
	if !bytes.Equal(sealed[:len(plaintext)], plaintext) {
		t.FailNow()
	}
}

func TestSymmetric(t *testing.T) {
	sym := func(keySize, blockSize int, c cipher.Block, nonce []byte) {
		f := func(
			plaintext, additionalData []byte,
			initials [][]byte,
			tagSize uint8,
		) bool {
			if len(plaintext) == 0 && len(additionalData) == 0 {
				return true
			}
			tagSize = 4 + tagSize%uint8(blockSize-4)
			aead, err := NewMGM(c, int(tagSize))
			if err != nil {
				return false
			}
			for _, initial := range initials {
				sealed := aead.Seal(initial, nonce, plaintext, additionalData)
				if !bytes.Equal(sealed[:len(initial)], initial) {
					return false
				}
				pt, err := aead.Open(
					sealed[:0],
					nonce,
					sealed[len(initial):],
					additionalData,
				)
				if err != nil || !bytes.Equal(pt, plaintext) {
					return false
				}
			}
			return true
		}
		if err := quick.Check(f, nil); err != nil {
			t.Error(err)
		}
	}

	key128 := new([gost3412128.KeySize]byte)
	rand.Read(key128[:])
	nonce := make([]byte, gost3412128.BlockSize)
	rand.Read(key128[1:])
	sym(
		gost3412128.KeySize,
		gost3412128.BlockSize,
		gost3412128.NewCipher(key128[:]),
		nonce[:gost3412128.BlockSize],
	)

	key64 := new([gost341264.KeySize]byte)
	copy(key64[:], key128[:])
	sym(
		gost341264.KeySize,
		gost341264.BlockSize,
		gost341264.NewCipher(key64[:]),
		nonce[:gost341264.BlockSize],
	)
}

func TestFastPathMatchesGeneric(t *testing.T) {
	tests := []struct {
		name  string
		block cipher.Block
	}{
		{
			name:  "kuznyechik",
			block: gost3412128.NewCipher(bytes.Repeat([]byte{0x42}, gost3412128.KeySize)),
		},
		{
			name:  "magma",
			block: gost341264.NewCipher(bytes.Repeat([]byte{0x24}, gost341264.KeySize)),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fast, err := NewMGM(tc.block, tc.block.BlockSize())
			if err != nil {
				t.Fatal(err)
			}
			generic, err := NewMGM(genericBlock{Block: tc.block}, tc.block.BlockSize())
			if err != nil {
				t.Fatal(err)
			}
			nonce := bytes.Repeat([]byte{0x35}, tc.block.BlockSize())
			nonce[0] &= 0x7f
			additionalData := bytes.Repeat([]byte{0xa6}, 2*tc.block.BlockSize()+3)
			for _, size := range []int{1, 7, 8, 15, 16, 63, 64, 1024, 1025} {
				plaintext := make([]byte, size)
				for i := range plaintext {
					plaintext[i] = byte(i*29 + size)
				}
				want := generic.Seal(nil, nonce, plaintext, additionalData)
				got := fast.Seal(nil, nonce, plaintext, additionalData)
				if !bytes.Equal(got, want) {
					t.Fatalf("size %d: fast Seal differs from generic", size)
				}

				opened, err := fast.Open(nil, nonce, got, additionalData)
				if err != nil {
					t.Fatalf("size %d: fast Open: %v", size, err)
				}
				if !bytes.Equal(opened, plaintext) {
					t.Fatalf("size %d: fast Open differs from plaintext", size)
				}

				const prefix = 5
				overlap := make([]byte, prefix+len(got))
				copy(overlap[prefix:], got)
				opened, err = fast.Open(overlap[:0], nonce, overlap[prefix:], additionalData)
				if err != nil {
					t.Fatalf("size %d: overlapping Open: %v", size, err)
				}
				if !bytes.Equal(opened, plaintext) {
					t.Fatalf("size %d: overlapping Open differs from plaintext", size)
				}
			}
		})
	}
}

func BenchmarkMGM64(b *testing.B) {
	key := make([]byte, gost341264.KeySize)
	rand.Read(key)
	nonce := make([]byte, gost341264.BlockSize)
	rand.Read(nonce)
	nonce[0] &= 0x7F
	pt := make([]byte, 1280+3)
	rand.Read(pt)
	c := gost341264.NewCipher(key)
	aead, err := NewMGM(c, gost341264.BlockSize)
	if err != nil {
		panic(err)
	}
	ct := make([]byte, len(pt)+aead.Overhead())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aead.Seal(ct[:0], nonce, pt, nil)
	}
}

func BenchmarkMGM128(b *testing.B) {
	key := make([]byte, gost3412128.KeySize)
	rand.Read(key)
	nonce := make([]byte, gost3412128.BlockSize)
	rand.Read(nonce)
	nonce[0] &= 0x7F
	pt := make([]byte, 1280+3)
	rand.Read(pt)
	c := gost3412128.NewCipher(key)
	aead, err := NewMGM(c, gost3412128.BlockSize)
	if err != nil {
		panic(err)
	}
	ct := make([]byte, len(pt)+aead.Overhead())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aead.Seal(ct[:0], nonce, pt, nil)
	}
}

func BenchmarkMGM128Sizes(b *testing.B) {
	key := make([]byte, gost3412128.KeySize)
	rand.Read(key)
	nonce := make([]byte, gost3412128.BlockSize)
	rand.Read(nonce)
	nonce[0] &= 0x7F
	c := gost3412128.NewCipher(key)
	aead, err := NewMGM(c, gost3412128.BlockSize)
	if err != nil {
		panic(err)
	}
	sizes := []struct {
		name string
		size int
	}{
		{"16B", 16},
		{"64B", 64},
		{"1KiB", 1024},
		{"16KiB", 16 * 1024},
	}

	for _, size := range sizes {
		pt := make([]byte, size.size)
		rand.Read(pt)
		ct := make([]byte, len(pt)+aead.Overhead())
		sealed := aead.Seal(nil, nonce, pt, nil)
		b.Run(size.name+"/seal", func(b *testing.B) {
			b.SetBytes(int64(len(pt)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				aead.Seal(ct[:0], nonce, pt, nil)
			}
		})
		b.Run(size.name+"/open", func(b *testing.B) {
			dst := make([]byte, 0, len(pt))
			b.SetBytes(int64(len(pt)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				out, err := aead.Open(dst[:0], nonce, sealed, nil)
				if err != nil || len(out) != len(pt) {
					b.Fatal("unexpected open result")
				}
			}
		})
	}
}
