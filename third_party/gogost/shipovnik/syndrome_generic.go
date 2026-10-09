package shipovnik

import (
	"encoding/binary"
)

// syndromeGeneric computes [H'|I] * vector. Its matrix and vector accesses do
// not depend on secret bits.
func syndromeGeneric(out, vector []byte) {
	clear(out)
	left := vector[:PublicKeySize]
	right := vector[PublicKeySize:]
	for row := 0; row < Dimension; row++ {
		base := row * PublicKeySize
		matrixRow := hPrime[base : base+PublicKeySize]
		_ = matrixRow[180]
		_ = left[180]
		folded := binary.LittleEndian.Uint64(matrixRow[0:])&binary.LittleEndian.Uint64(left[0:]) ^
			binary.LittleEndian.Uint64(matrixRow[8:])&binary.LittleEndian.Uint64(left[8:]) ^
			binary.LittleEndian.Uint64(matrixRow[16:])&binary.LittleEndian.Uint64(left[16:]) ^
			binary.LittleEndian.Uint64(matrixRow[24:])&binary.LittleEndian.Uint64(left[24:]) ^
			binary.LittleEndian.Uint64(matrixRow[32:])&binary.LittleEndian.Uint64(left[32:]) ^
			binary.LittleEndian.Uint64(matrixRow[40:])&binary.LittleEndian.Uint64(left[40:]) ^
			binary.LittleEndian.Uint64(matrixRow[48:])&binary.LittleEndian.Uint64(left[48:]) ^
			binary.LittleEndian.Uint64(matrixRow[56:])&binary.LittleEndian.Uint64(left[56:]) ^
			binary.LittleEndian.Uint64(matrixRow[64:])&binary.LittleEndian.Uint64(left[64:]) ^
			binary.LittleEndian.Uint64(matrixRow[72:])&binary.LittleEndian.Uint64(left[72:]) ^
			binary.LittleEndian.Uint64(matrixRow[80:])&binary.LittleEndian.Uint64(left[80:]) ^
			binary.LittleEndian.Uint64(matrixRow[88:])&binary.LittleEndian.Uint64(left[88:]) ^
			binary.LittleEndian.Uint64(matrixRow[96:])&binary.LittleEndian.Uint64(left[96:]) ^
			binary.LittleEndian.Uint64(matrixRow[104:])&binary.LittleEndian.Uint64(left[104:]) ^
			binary.LittleEndian.Uint64(matrixRow[112:])&binary.LittleEndian.Uint64(left[112:]) ^
			binary.LittleEndian.Uint64(matrixRow[120:])&binary.LittleEndian.Uint64(left[120:]) ^
			binary.LittleEndian.Uint64(matrixRow[128:])&binary.LittleEndian.Uint64(left[128:]) ^
			binary.LittleEndian.Uint64(matrixRow[136:])&binary.LittleEndian.Uint64(left[136:]) ^
			binary.LittleEndian.Uint64(matrixRow[144:])&binary.LittleEndian.Uint64(left[144:]) ^
			binary.LittleEndian.Uint64(matrixRow[152:])&binary.LittleEndian.Uint64(left[152:]) ^
			binary.LittleEndian.Uint64(matrixRow[160:])&binary.LittleEndian.Uint64(left[160:]) ^
			binary.LittleEndian.Uint64(matrixRow[168:])&binary.LittleEndian.Uint64(left[168:])
		folded ^= uint64((matrixRow[176] & left[176]) ^
			(matrixRow[177] & left[177]) ^
			(matrixRow[178] & left[178]) ^
			(matrixRow[179] & left[179]) ^
			(matrixRow[180] & left[180]))
		parity := parity64(folded)
		parity ^= (right[row>>3] >> (7 - uint(row&7))) & 1
		out[row>>3] |= parity << (7 - uint(row&7))
	}
}

// parity64 returns the parity of x without feature-dependent instructions,
// secret-dependent branches, or table lookups.
func parity64(x uint64) byte {
	x ^= x >> 32
	x ^= x >> 16
	x ^= x >> 8
	x ^= x >> 4
	return byte((uint64(0x6996) >> (x & 0x0f)) & 1)
}
