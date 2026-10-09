//go:build amd64 && !purego && gostsimdresearch
// +build amd64,!purego,gostsimdresearch

package gost3412128

import (
	"bytes"
	"testing"
)

//go:noescape
func encryptBlockSSEStackUnrolled(dst, src *[16]byte, rkeys *[10][16]byte)

//go:noescape
func decryptBlockSSEStackUnrolled(dst, src *[16]byte, rkeys *[10][16]byte)

type kuzFoldedSingleBlock struct {
	enc        [9][16][256]lookupBlock64
	dec        [8][16][256]lookupBlock64
	decFinal   [16][256]byte
	encFinalLo uint64
	encFinalHi uint64
}

func newKuzFoldedSingleBlock(c *Cipher) *kuzFoldedSingleBlock {
	initCipherTables()
	f := new(kuzFoldedSingleBlock)
	for round := 0; round < 9; round++ {
		for pos := 0; pos < BlockSize; pos++ {
			key := c.ks[round][pos]
			for b := 0; b < 256; b++ {
				f.enc[round][pos][b] = lsEncLookup64[pos][byte(b)^key]
			}
		}
	}
	f.encFinalLo, f.encFinalHi = getBlock64(&c.ks[9])

	for round, keyIndex := range [...]int{9, 8, 7, 6, 5, 4, 3, 2} {
		for pos := 0; pos < BlockSize; pos++ {
			key := c.decKs[keyIndex][pos]
			for b := 0; b < 256; b++ {
				f.dec[round][pos][b] = slDecLookup64[pos][byte(b)^key]
			}
		}
	}
	for pos := 0; pos < BlockSize; pos++ {
		key1 := c.decKs[1][pos]
		key0 := c.decKs[0][pos]
		for b := 0; b < 256; b++ {
			f.decFinal[pos][b] = piInverseTable[byte(b)^key1] ^ key0
		}
	}
	return f
}

func (f *kuzFoldedSingleBlock) encrypt(dst, src *[16]byte) {
	lo, hi := getBlock64(src)
	lo, hi = lookupTableWords64(lo, hi, &f.enc[0])
	lo, hi = lookupTableWords64(lo, hi, &f.enc[1])
	lo, hi = lookupTableWords64(lo, hi, &f.enc[2])
	lo, hi = lookupTableWords64(lo, hi, &f.enc[3])
	lo, hi = lookupTableWords64(lo, hi, &f.enc[4])
	lo, hi = lookupTableWords64(lo, hi, &f.enc[5])
	lo, hi = lookupTableWords64(lo, hi, &f.enc[6])
	lo, hi = lookupTableWords64(lo, hi, &f.enc[7])
	lo, hi = lookupTableWords64(lo, hi, &f.enc[8])
	putBlock64(dst, lo^f.encFinalLo, hi^f.encFinalHi)
}

func (f *kuzFoldedSingleBlock) decrypt(dst, src *[16]byte) {
	lo, hi := getBlock64(src)
	lo, hi = lookupTableWords64(lo, hi, &lInvLookup64)
	lo, hi = lookupTableWords64(lo, hi, &f.dec[0])
	lo, hi = lookupTableWords64(lo, hi, &f.dec[1])
	lo, hi = lookupTableWords64(lo, hi, &f.dec[2])
	lo, hi = lookupTableWords64(lo, hi, &f.dec[3])
	lo, hi = lookupTableWords64(lo, hi, &f.dec[4])
	lo, hi = lookupTableWords64(lo, hi, &f.dec[5])
	lo, hi = lookupTableWords64(lo, hi, &f.dec[6])
	lo, hi = lookupTableWords64(lo, hi, &f.dec[7])

	dst[0] = f.decFinal[0][byte(lo)]
	dst[1] = f.decFinal[1][byte(lo>>8)]
	dst[2] = f.decFinal[2][byte(lo>>16)]
	dst[3] = f.decFinal[3][byte(lo>>24)]
	dst[4] = f.decFinal[4][byte(lo>>32)]
	dst[5] = f.decFinal[5][byte(lo>>40)]
	dst[6] = f.decFinal[6][byte(lo>>48)]
	dst[7] = f.decFinal[7][byte(lo>>56)]
	dst[8] = f.decFinal[8][byte(hi)]
	dst[9] = f.decFinal[9][byte(hi>>8)]
	dst[10] = f.decFinal[10][byte(hi>>16)]
	dst[11] = f.decFinal[11][byte(hi>>24)]
	dst[12] = f.decFinal[12][byte(hi>>32)]
	dst[13] = f.decFinal[13][byte(hi>>40)]
	dst[14] = f.decFinal[14][byte(hi>>48)]
	dst[15] = f.decFinal[15][byte(hi>>56)]
}

func TestSingleBlockResearchEquivalent(t *testing.T) {
	key := make([]byte, KeySize)
	copy(key, Key)
	c := NewCipher(key)
	folded := newKuzFoldedSingleBlock(c)

	for i := 0; i < 256; i++ {
		var src, want, got [BlockSize]byte
		for j := range src {
			src[j] = byte(i*17 + j*31)
		}
		encryptBlockSSEStack(&want, &src, &c.ks)
		encryptBlockSSEStackUnrolled(&got, &src, &c.ks)
		if !bytes.Equal(got[:], want[:]) {
			t.Fatalf("unrolled encrypt mismatch")
		}
		folded.encrypt(&got, &src)
		if !bytes.Equal(got[:], want[:]) {
			t.Fatalf("folded encrypt mismatch")
		}

		decryptBlockSSEStack(&want, &got, &c.decKs)
		decryptBlockSSEStackUnrolled(&src, &got, &c.decKs)
		if !bytes.Equal(src[:], want[:]) {
			t.Fatalf("unrolled decrypt mismatch")
		}
		folded.decrypt(&src, &got)
		if !bytes.Equal(src[:], want[:]) {
			t.Fatalf("folded decrypt mismatch")
		}
	}
}

func BenchmarkSingleBlockResearch(b *testing.B) {
	key := make([]byte, KeySize)
	copy(key, Key)
	c := NewCipher(key)
	folded := newKuzFoldedSingleBlock(c)

	b.Run("Encrypt/SSEStack", func(b *testing.B) {
		blk := pt
		b.SetBytes(BlockSize)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			encryptBlockSSEStack(&blk, &blk, &c.ks)
		}
		blockBenchSink = blk
	})
	b.Run("Encrypt/SSEStackUnrolled", func(b *testing.B) {
		blk := pt
		b.SetBytes(BlockSize)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			encryptBlockSSEStackUnrolled(&blk, &blk, &c.ks)
		}
		blockBenchSink = blk
	})
	b.Run("Encrypt/FoldedGo", func(b *testing.B) {
		blk := pt
		b.SetBytes(BlockSize)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			folded.encrypt(&blk, &blk)
		}
		blockBenchSink = blk
	})
	b.Run("Decrypt/SSEStack", func(b *testing.B) {
		blk := ct
		b.SetBytes(BlockSize)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			decryptBlockSSEStack(&blk, &blk, &c.decKs)
		}
		blockBenchSink = blk
	})
	b.Run("Decrypt/SSEStackUnrolled", func(b *testing.B) {
		blk := ct
		b.SetBytes(BlockSize)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			decryptBlockSSEStackUnrolled(&blk, &blk, &c.decKs)
		}
		blockBenchSink = blk
	})
	b.Run("Decrypt/FoldedGo", func(b *testing.B) {
		blk := ct
		b.SetBytes(BlockSize)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			folded.decrypt(&blk, &blk)
		}
		blockBenchSink = blk
	})
}
