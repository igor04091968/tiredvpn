//go:build amd64 && !purego

package yescrypt

import "testing"

func TestXORWordsAMD64(t *testing.T) {
	for _, words := range []int{8, 16, 128} {
		dst := make([]uint64, words+2)
		src := make([]uint64, words+2)
		want := make([]uint64, words+2)
		for i := range dst {
			dst[i] = uint64(i)*0x9e3779b97f4a7c15 + 1
			src[i] = uint64(i)*0xd6e8feb86659fd93 + 3
		}
		copy(want, dst)
		for i := range words {
			want[i+1] ^= src[i+1]
		}

		xorWords(dst[1:], src[1:], words)
		for i := range dst {
			if dst[i] != want[i] {
				t.Fatalf("words=%d index=%d: got %x, want %x", words, i, dst[i], want[i])
			}
		}
	}
}
