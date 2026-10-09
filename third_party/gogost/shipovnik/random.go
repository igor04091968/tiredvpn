package shipovnik

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
)

type entropySource struct {
	ctx context.Context
	r   io.Reader
	buf [4096]byte
	off int
	n   int
}

func newEntropySource(ctx context.Context, r io.Reader) (*entropySource, error) {
	if r == nil {
		return nil, ErrInvalidRandom
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return &entropySource{ctx: ctx, r: r}, nil
}

func (s *entropySource) read(p []byte) error {
	for len(p) != 0 {
		if err := s.ctx.Err(); err != nil {
			return err
		}
		if s.off == s.n {
			n, err := io.ReadFull(s.r, s.buf[:])
			if err != nil {
				clear(s.buf[:])
				return fmt.Errorf("shipovnik: entropy: %w", err)
			}
			s.off, s.n = 0, n
		}
		n := copy(p, s.buf[s.off:s.n])
		s.off += n
		p = p[n:]
	}
	return nil
}

func (s *entropySource) uint16() (uint16, error) {
	if s.n-s.off >= 2 {
		x := binary.LittleEndian.Uint16(s.buf[s.off : s.off+2])
		s.off += 2
		return x, nil
	}
	var b [2]byte
	if err := s.read(b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(b[:]), nil
}

// uniform returns an unbiased integer in [0,n). All Shipovnik ranges fit in
// 16 bits, so Lemire's multiply-high mapping consumes half as much entropy as
// the 32-bit form. The low product word is rejection-sampled below the exact
// threshold; division remains off the overwhelmingly common acceptance path.
func (s *entropySource) uniform(n uint16) (uint16, error) {
	if n == 0 {
		panic("shipovnik: uniform called with zero range")
	}
	x, err := s.uint16()
	if err != nil {
		return 0, err
	}
	product := uint32(x) * uint32(n)
	low := uint16(product)
	if low < n {
		threshold := -n % n
		for low < threshold {
			x, err = s.uint16()
			if err != nil {
				return 0, err
			}
			product = uint32(x) * uint32(n)
			low = uint16(product)
		}
	}
	return uint16(product >> 16), nil
}

func (s *entropySource) close() { clear(s.buf[:]) }

func generateFixedWeightSecret(s *entropySource, secret []byte) error {
	clear(secret)
	var indices [CodeLength]uint16
	copy(indices[:], identityPermutation[:])
	defer clear(indices[:])
	for i := 0; i < SecretWeight; i++ {
		if i&63 == 0 {
			if err := s.ctx.Err(); err != nil {
				return err
			}
		}
		offset, err := s.uniform(uint16(CodeLength - i))
		if err != nil {
			return err
		}
		j := i + int(offset)
		indices[i], indices[j] = indices[j], indices[i]
		setBit(secret, int(indices[i]))
	}
	return nil
}

var identityPermutation = func() [CodeLength]uint16 {
	var permutation [CodeLength]uint16
	for i := range permutation {
		permutation[i] = uint16(i)
	}
	return permutation
}()

func generatePermutation(s *entropySource, permutation []uint16) error {
	copy(permutation, identityPermutation[:])
	for i := len(permutation) - 1; i > 0; i-- {
		if i&255 == 0 {
			if err := s.ctx.Err(); err != nil {
				return err
			}
		}
		j, err := s.uniform(uint16(i + 1))
		if err != nil {
			return err
		}
		permutation[i], permutation[j] = permutation[j], permutation[i]
	}
	return nil
}
