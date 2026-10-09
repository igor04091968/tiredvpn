package shipovnik

import (
	"context"
	"encoding/binary"
	"math/bits"

	"gitverse.ru/uzer_007/gogost/v3/internal/gost34112012"
)

func hashOne(part []byte) [hashSize]byte {
	return gost34112012.Sum512(part)
}

func hashPair(first, second []byte) [hashSize]byte {
	h := gost34112012.NewValue(hashSize)
	_, _ = h.Write(first)
	_, _ = h.Write(second)
	var sum [hashSize]byte
	_ = h.Sum(sum[:0])
	return sum
}

func hashMessageCommitments(ctx context.Context, message, commitments []byte) ([hashSize]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	h := gost34112012.NewValue(hashSize)
	for _, part := range [][]byte{message, commitments} {
		for len(part) != 0 {
			if err := ctx.Err(); err != nil {
				return [hashSize]byte{}, err
			}
			n := len(part)
			if n > 64<<10 {
				n = 64 << 10
			}
			_, _ = h.Write(part[:n])
			part = part[n:]
		}
	}
	var sum [hashSize]byte
	_ = h.Sum(sum[:0])
	return sum, nil
}

// challengeTritsTo maps a 512-bit big-endian hash to
// floor(h*3^delta/2^512) and writes exactly delta base-3 digits to dst. The
// digits are the base-3 fractional expansion of h/2^512: each fixed-width
// multiplication by three emits the next digit as its carry. This is
// allocation-free and avoids variable-width division.
func challengeTritsTo(dst []byte, scheme Scheme, hash [hashSize]byte) []byte {
	rounds := scheme.Rounds()
	dst = dst[:rounds]
	var fraction [hashSize / 8]uint64
	for i := range fraction {
		fraction[i] = binary.BigEndian.Uint64(hash[(len(fraction)-1-i)*8:])
	}
	for digit := range dst {
		var carry uint64
		for limb := range fraction {
			hi, lo := bits.Mul64(fraction[limb], 3)
			lo, overflow := bits.Add64(lo, carry, 0)
			fraction[limb] = lo
			carry = hi + overflow
		}
		dst[digit] = byte(carry)
	}
	return dst
}

func challengeTrits(scheme Scheme, hash [hashSize]byte) []byte {
	return challengeTritsTo(make([]byte, scheme.Rounds()), scheme, hash)
}
