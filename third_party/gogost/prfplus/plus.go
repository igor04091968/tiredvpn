package prfplus

type PRFForPlus interface {
	BlockSize() int
	Derive(salt []byte) []byte
}

type prfForPlusInto interface {
	DeriveTo(dst, salt []byte) []byte
}

// PRFPlus реализует функцию prf+, определённую в RFC 7296 (IKEv2).
func PRFPlus(prf PRFForPlus, dst, salt []byte) {
	in := make([]byte, prf.BlockSize()+len(salt)+1)
	in[len(in)-1] = byte(0x01)
	copy(in[prf.BlockSize():], salt)
	copy(in[:prf.BlockSize()], derivePRFPlusBlock(prf, in[:0], in[prf.BlockSize():]))
	copy(dst, in[:prf.BlockSize()])
	n := len(dst) / prf.BlockSize()
	if n == 0 {
		return
	}
	if n*prf.BlockSize() != len(dst) {
		n++
	}
	n--
	out := dst[prf.BlockSize():]
	for i := range n {
		in[len(in)-1] = byte(i + 2)
		copy(in[:prf.BlockSize()], derivePRFPlusBlock(prf, in[:0], in))
		copy(out, in[:prf.BlockSize()])
		if i+1 != n {
			out = out[prf.BlockSize():]
		}
	}
}

func derivePRFPlusBlock(prf PRFForPlus, dst, salt []byte) []byte {
	if prfInto, ok := prf.(prfForPlusInto); ok {
		return prfInto.DeriveTo(dst, salt)
	}
	return append(dst, prf.Derive(salt)...)
}
