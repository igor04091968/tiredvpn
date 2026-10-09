//go:build amd64 && !purego
// +build amd64,!purego

package gost3412128

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

func TestSSEStackMatchesVectors(t *testing.T) {
	c := NewCipher(Key)

	var stack [BlockSize]byte
	encryptBlockSSEStack(&stack, &pt, &c.ks)
	if !bytes.Equal(stack[:], ct[:]) {
		t.Fatalf("SSEStack encrypt mismatch: got %x, want %x", stack, ct)
	}

	decryptBlockSSEStack(&stack, &ct, &c.decKs)
	if !bytes.Equal(stack[:], pt[:]) {
		t.Fatalf("SSEStack decrypt mismatch: got %x, want %x", stack, pt)
	}

	var key [KeySize]byte
	var block [BlockSize]byte
	for i := 0; i < 128; i++ {
		rand.Read(key[:])
		rand.Read(block[:])
		keys := stretchKey(key)
		decKeys := decryptRoundKeys(keys)
		encryptBlockSSEStack(&stack, &block, &keys)
		var plain [BlockSize]byte
		decryptBlockSSEStack(&plain, &stack, &decKeys)
		if !bytes.Equal(plain[:], block[:]) {
			t.Fatalf("SSEStack random round-trip mismatch at case %d", i)
		}
	}
}

func TestCMBackendsMatch(t *testing.T) {
	var key [KeySize]byte
	copy(key[:], Key)
	rkeys := stretchKey(key)

	for _, size := range []int{0, 1, 15, 16, 17, 64, 1024, 4097, 16*1024 + 11} {
		src := make([]byte, size)
		if _, err := rand.Read(src); err != nil {
			t.Fatal(err)
		}
		sse := append([]byte(nil), src...)
		avx2 := append([]byte(nil), src...)
		xorKeyStreamInPlaceSSE(sse, 0x0102030405060708, &rkeys)
		if hasAVX2() {
			xorKeyStreamInPlaceAVX2(avx2, 0x0102030405060708, &rkeys)
		} else {
			xorKeyStreamInPlaceSSE(avx2, 0x0102030405060708, &rkeys)
		}
		if !bytes.Equal(avx2, sse) {
			t.Fatalf("CM backend mismatch for size %d", size)
		}
	}
}

func TestAVX2PairLUTBlocksEquivalent(t *testing.T) {
	if !hasAVX2() {
		t.Skip("AVX2 is not available")
	}
	ensureEncryptPairLookup()
	ensureDecryptPairLookup()

	c := NewCipher(Key)
	for _, size := range []int{0, 64, 128, 1024, 1 << 20} {
		src := make([]byte, size)
		if _, err := rand.Read(src); err != nil {
			t.Fatal(err)
		}
		want := make([]byte, size)
		for off := 0; off < len(src); off += BlockSize {
			c.Encrypt(want[off:off+BlockSize], src[off:off+BlockSize])
		}
		got := make([]byte, size)
		if size > 0 {
			encryptBlocksAVX2PairLUTBlocks4(got, src, &c.ks)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("AVX2 pair-LUT mismatch for size %d", size)
		}
		if size >= 128 {
			for i := range got {
				got[i] = 0
			}
			encryptBlocksAVX2PairLUTBlocks8(got, src, &c.ks)
			if !bytes.Equal(got, want) {
				t.Fatalf("AVX2 pair-LUT x8 mismatch for size %d", size)
			}
		}
		ciphertext := want
		wantPlain := make([]byte, size)
		for off := 0; off < len(ciphertext); off += BlockSize {
			c.Decrypt(wantPlain[off:off+BlockSize], ciphertext[off:off+BlockSize])
		}
		if size > 0 {
			for i := range got {
				got[i] = 0
			}
			decryptBlocksAVX2PairLUTBlocks4(got, ciphertext, &c.decKs)
			if !bytes.Equal(got, wantPlain) {
				t.Fatalf("AVX2 decrypt pair-LUT mismatch for size %d", size)
			}
		}
		if size >= 128 {
			for i := range got {
				got[i] = 0
			}
			decryptBlocksAVX2PairLUTBlocks8(got, ciphertext, &c.decKs)
			if !bytes.Equal(got, wantPlain) {
				t.Fatalf("AVX2 decrypt pair-LUT x8 mismatch for size %d", size)
			}
		}
	}
}

func BenchmarkEncryptBlocksAVX2PairLUT(b *testing.B) {
	if !hasAVX2() {
		b.Skip("AVX2 is not available")
	}
	ensureEncryptPairLookup()

	key := make([]byte, KeySize)
	copy(key, Key)
	c := NewCipher(key)
	for _, size := range []struct {
		name string
		n    int
	}{
		{"64B", 64},
		{"128B", 128},
		{"1KiB", 1024},
		{"16KiB", 16 * 1024},
		{"1MiB", 1 << 20},
	} {
		src := make([]byte, size.n)
		dst := make([]byte, size.n)
		for i := range src {
			src[i] = byte(i*31 + 17)
		}
		b.Run(size.name, func(b *testing.B) {
			n := len(src) &^ (4*BlockSize - 1)
			b.SetBytes(int64(n))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				encryptBlocksAVX2PairLUTBlocks4(dst[:n], src[:n], &c.ks)
			}
			copy(benchKuznechikBlocksOut[:], dst[:n])
		})
		if size.n >= 8*BlockSize {
			b.Run("x8/"+size.name, func(b *testing.B) {
				n := len(src) &^ (8*BlockSize - 1)
				b.SetBytes(int64(n))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					encryptBlocksAVX2PairLUTBlocks8(dst[:n], src[:n], &c.ks)
				}
				copy(benchKuznechikBlocksOut[:], dst[:n])
			})
		}
	}
}

func BenchmarkEncryptBlocksAVX2Compact(b *testing.B) {
	if !hasAVX2() {
		b.Skip("AVX2 is not available")
	}
	key := make([]byte, KeySize)
	copy(key, Key)
	c := NewCipher(key)
	for _, size := range []int{8 * BlockSize, 64 * BlockSize, 1024 * BlockSize} {
		src := make([]byte, size)
		dst := make([]byte, size)
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for range b.N {
				encryptBlocksAVX2Blocks8(dst, src, &c.ks)
			}
			copy(benchKuznechikBlocksOut[:], dst)
		})
	}
}

func BenchmarkDecryptBlocksAVX2PairLUT(b *testing.B) {
	if !hasAVX2() {
		b.Skip("AVX2 is not available")
	}
	ensureDecryptPairLookup()

	key := make([]byte, KeySize)
	copy(key, Key)
	c := NewCipher(key)
	for _, size := range []struct {
		name string
		n    int
	}{
		{"64B", 64},
		{"128B", 128},
		{"1KiB", 1024},
		{"16KiB", 16 * 1024},
		{"1MiB", 1 << 20},
	} {
		src := make([]byte, size.n)
		encrypted := make([]byte, size.n)
		dst := make([]byte, size.n)
		for i := range src {
			src[i] = byte(i*31 + 17)
		}
		c.EncryptBlocks(encrypted, src)
		b.Run(size.name, func(b *testing.B) {
			n := len(encrypted) &^ (4*BlockSize - 1)
			b.SetBytes(int64(n))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				decryptBlocksAVX2PairLUTBlocks4(dst[:n], encrypted[:n], &c.decKs)
			}
			copy(benchKuznechikBlocksOut[:], dst[:n])
		})
		if size.n >= 8*BlockSize {
			b.Run("x8/"+size.name, func(b *testing.B) {
				n := len(encrypted) &^ (8*BlockSize - 1)
				b.SetBytes(int64(n))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					decryptBlocksAVX2PairLUTBlocks8(dst[:n], encrypted[:n], &c.decKs)
				}
				copy(benchKuznechikBlocksOut[:], dst[:n])
			})
		}
	}
}

func BenchmarkEncryptSSEStack(b *testing.B) {
	key := make([]byte, KeySize)
	copy(key, Key)
	c := NewCipher(key)
	blk := pt
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encryptBlockSSEStack(&blk, &blk, &c.ks)
	}
}

func BenchmarkEncryptLookup(b *testing.B) {
	key := make([]byte, KeySize)
	copy(key, Key)
	c := NewCipher(key)
	blk := pt
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encryptBlockLookup(&blk, &blk, &c.ks)
	}
}

func BenchmarkDecryptSSEStack(b *testing.B) {
	key := make([]byte, KeySize)
	copy(key, Key)
	c := NewCipher(key)
	blk := ct
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decryptBlockSSEStack(&blk, &blk, &c.decKs)
	}
}

func BenchmarkDecryptLookup(b *testing.B) {
	key := make([]byte, KeySize)
	copy(key, Key)
	c := NewCipher(key)
	blk := ct
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decryptBlockLookup(&blk, &blk, &c.decKs)
	}
}

func BenchmarkCMBackendSSE(b *testing.B) {
	benchmarkCMBackend(b, "sse", xorKeyStreamInPlaceSSE)
}

func BenchmarkCMBackendAVX2(b *testing.B) {
	if !hasAVX2() {
		b.Skip("AVX2 is not available")
	}
	benchmarkCMBackend(b, "avx2", xorKeyStreamInPlaceAVX2)
}

func benchmarkCMBackend(b *testing.B, name string, xor func([]byte, uint64, *[10][16]byte)) {
	sizes := []int{BlockSize, 64, 1024, 4 * 1024, 16 * 1024, 64 * 1024, 1024 * 1024}
	key := [KeySize]byte(Key)
	rkeys := stretchKey(key)

	for _, size := range sizes {
		b.Run(fmt.Sprintf("%s/%dB", name, size), func(b *testing.B) {
			buf := make([]byte, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				xor(buf, 0x0102030405060708, &rkeys)
			}
		})
	}
}
