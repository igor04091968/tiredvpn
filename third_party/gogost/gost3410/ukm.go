package gost3410

import (
	"math/big"
)

// NewUKM разбирает little-endian значение пользовательского ключевого материала.
func NewUKM(raw []byte) *big.Int {
	t := make([]byte, len(raw))
	for i := range len(t) {
		t[i] = raw[len(raw)-i-1]
	}
	return bytes2big(t)
}
