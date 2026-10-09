package shipovnik

import (
	"crypto/sha256"
	_ "embed"
)

const hPrimeSHA256 = "47571b2e293a0fe90d678341861e9a1080c80c799d3dba6f5964f6dad2a15e62"

// hPrime is the canonical row-major QAPP matrix. See NOTICE and
// internal/cmd/genmatrix for provenance and reproducible generation.
//
//go:embed h_prime.bin
var hPrime []byte

func init() {
	if len(hPrime) != matrixSize {
		panic("shipovnik: embedded H' matrix has invalid size")
	}
	if got := sha256.Sum256(hPrime); stringHex(got[:]) != hPrimeSHA256 {
		panic("shipovnik: embedded H' matrix checksum mismatch")
	}
}

func stringHex(p []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(p)*2)
	for i, b := range p {
		out[2*i] = digits[b>>4]
		out[2*i+1] = digits[b&15]
	}
	return string(out)
}
