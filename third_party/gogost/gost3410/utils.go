package gost3410

import (
	"math/big"
)

func bytes2big(d []byte) *big.Int {
	return big.NewInt(0).SetBytes(d)
}

func reverse(d []byte) {
	for i, j := 0, len(d)-1; i < j; i, j = i+1, j-1 {
		d[i], d[j] = d[j], d[i]
	}
}

func pad(d []byte, size int) []byte {
	return append(make([]byte, size-len(d)), d...)
}

func pointSize(p *big.Int) int {
	if p.BitLen() > 256 {
		return 64
	}
	return 32
}
