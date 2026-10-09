//go:build amd64 && !purego && gostsimdresearch
// +build amd64,!purego,gostsimdresearch

package gost341264

import (
	"bytes"
	"testing"
)

type magmaFoldedRound struct {
	lo [1 << 16]uint64
	hi [2][1 << 16]word
}

type magmaFoldedSchedule struct {
	rounds [32]*magmaFoldedRound
}

func newMagmaFoldedSchedule(keys *[32]word, t16 *magmaT16Table) *magmaFoldedSchedule {
	s := new(magmaFoldedSchedule)
	for round := 0; round < 32; round++ {
		r := new(magmaFoldedRound)
		key := uint32(keys[round])
		keyLo := key & 0xffff
		keyHi := key >> 16
		for n := 0; n < 1<<16; n++ {
			sum := uint32(n) + keyLo
			r.lo[n] = uint64(t16[0][uint16(sum)]) | uint64(sum>>16)<<32
		}
		for carry := 0; carry < 2; carry++ {
			for n := 0; n < 1<<16; n++ {
				r.hi[carry][n] = t16[1][uint16(uint32(n)+keyHi+uint32(carry))]
			}
		}
		s.rounds[round] = r
	}
	return s
}

func (s *magmaFoldedSchedule) crypt(n1, n2 word) (word, word) {
	for round := 0; round < 32; round++ {
		r := s.rounds[round]
		lo := r.lo[uint16(n1)]
		f := word(lo) ^ r.hi[int(lo>>32)][uint16(n1>>16)]
		n1, n2 = f^n2, n1
	}
	return n1, n2
}

func cryptBlocksFoldedT16Research(dst, src []byte, sched *magmaFoldedSchedule) {
	for len(src) >= BlockSize {
		n1, n2 := sched.crypt(word(load32BE(src[4:8])), word(load32BE(src[0:4])))
		store32BE(dst[0:4], uint32(n1))
		store32BE(dst[4:8], uint32(n2))
		dst = dst[BlockSize:]
		src = src[BlockSize:]
	}
}

func TestFoldedT16ResearchEquivalent(t *testing.T) {
	c := NewCipher(benchMagmaKey())
	enc := newMagmaFoldedSchedule(&c.encKeys, c.t16)
	dec := newMagmaFoldedSchedule(&c.decKeys, c.t16)

	src := benchMagmaData(32 * BlockSize)
	want := make([]byte, len(src))
	got := make([]byte, len(src))
	c.EncryptBlocks(want, src)
	cryptBlocksFoldedT16Research(got, src, enc)
	if !bytes.Equal(got, want) {
		t.Fatalf("folded encrypt mismatch")
	}
	plain := make([]byte, len(src))
	cryptBlocksFoldedT16Research(plain, got, dec)
	if !bytes.Equal(plain, src) {
		t.Fatalf("folded decrypt mismatch")
	}
}

func BenchmarkFoldedT16Research(b *testing.B) {
	c := NewCipher(benchMagmaKey())
	enc := newMagmaFoldedSchedule(&c.encKeys, c.t16)
	dec := newMagmaFoldedSchedule(&c.decKeys, c.t16)
	for _, size := range []struct {
		name string
		n    int
	}{
		{"8B", 8},
		{"64B", 64},
		{"128B", 128},
		{"1KiB", 1024},
		{"16KiB", 16 * 1024},
		{"1MiB", 1 << 20},
	} {
		src := benchMagmaData(size.n)
		dst := make([]byte, size.n)
		encrypted := make([]byte, size.n)
		c.EncryptBlocks(encrypted, src)
		b.Run("Encrypt/"+size.name, func(b *testing.B) {
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				cryptBlocksFoldedT16Research(dst, src, enc)
			}
			copy(benchMagmaOut[:], dst)
		})
		b.Run("Decrypt/"+size.name, func(b *testing.B) {
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				cryptBlocksFoldedT16Research(dst, encrypted, dec)
			}
			copy(benchMagmaOut[:], dst)
		})
	}
}
