//go:build amd64 && !purego

#include "textflag.h"

// func gfMul64PCLMUL(x, y uint64) uint64
// The field polynomial is x^64 + x^4 + x^3 + x + 1 (0x1b).
TEXT ·gfMul64PCLMUL(SB), NOSPLIT, $0-24
	MOVQ x+0(FP), X0
	MOVQ y+8(FP), X1
	PCLMULQDQ $0x00, X1, X0

	MOVQ X0, AX // low product limb
	PSRLDQ $8, X0
	MOVQ X0, CX // high product limb

	// Reduce high * (1 + x + x^3 + x^4).
	MOVQ CX, DX
	MOVQ CX, BX
	SHLQ $1, BX
	XORQ BX, DX
	MOVQ CX, BX
	SHLQ $3, BX
	XORQ BX, DX
	MOVQ CX, BX
	SHLQ $4, BX
	XORQ BX, DX

	// Fold the at most four overflow bits once more.
	MOVQ CX, R8
	SHRQ $63, R8
	MOVQ CX, R9
	SHRQ $61, R9
	XORQ R9, R8
	MOVQ CX, R9
	SHRQ $60, R9
	XORQ R9, R8
	MOVQ R8, R10
	MOVQ R10, R9
	SHLQ $1, R9
	XORQ R9, R8
	MOVQ R10, R9
	SHLQ $3, R9
	XORQ R9, R8
	SHLQ $4, R10
	XORQ R10, R8

	XORQ DX, AX
	XORQ R8, AX
	MOVQ AX, ret+16(FP)
	RET

// func gfMul128PCLMUL(xHi, xLo, yHi, yLo uint64) (zHi, zLo uint64)
// The field polynomial is x^128 + x^7 + x^2 + x + 1 (0x87).
TEXT ·gfMul128PCLMUL(SB), NOSPLIT, $0-48
	MOVQ xLo+8(FP), X0
	MOVQ xHi+0(FP), AX
	PINSRQ $1, AX, X0
	MOVQ yLo+24(FP), X1
	MOVQ yHi+16(FP), AX
	PINSRQ $1, AX, X1

	// Karatsuba carry-less multiplication: p0, p2 and cross product.
	MOVOU X0, X2
	MOVOU X0, X3
	PCLMULQDQ $0x00, X1, X2 // p0
	PCLMULQDQ $0x11, X1, X3 // p2

	MOVOU X0, X4
	PSRLDQ $8, X4
	PXOR X0, X4
	MOVOU X1, X5
	PSRLDQ $8, X5
	PXOR X1, X5
	PCLMULQDQ $0x00, X5, X4
	PXOR X2, X4
	PXOR X3, X4 // p1

	MOVOU X4, X5
	PSLLDQ $8, X5
	PXOR X5, X2 // low 128 bits
	PSRLDQ $8, X4
	PXOR X4, X3 // high 128 bits

	MOVQ X2, AX // r0
	PSRLDQ $8, X2
	MOVQ X2, BX // r1
	MOVQ X3, CX // h0
	PSRLDQ $8, X3
	MOVQ X3, DX // h1

	// t = H * (1 + x + x^2 + x^7), retaining its low 128 bits.
	MOVQ CX, R8
	MOVQ CX, R9
	SHLQ $1, R9
	XORQ R9, R8
	MOVQ CX, R9
	SHLQ $2, R9
	XORQ R9, R8
	MOVQ CX, R9
	SHLQ $7, R9
	XORQ R9, R8 // t0

	MOVQ DX, R10
	MOVQ DX, R11
	SHLQ $1, R11
	XORQ R11, R10
	MOVQ DX, R11
	SHLQ $2, R11
	XORQ R11, R10
	MOVQ DX, R11
	SHLQ $7, R11
	XORQ R11, R10
	MOVQ CX, R11
	SHRQ $63, R11
	XORQ R11, R10
	MOVQ CX, R11
	SHRQ $62, R11
	XORQ R11, R10
	MOVQ CX, R11
	SHRQ $57, R11
	XORQ R11, R10 // t1

	// q contains the overflow above bit 127; fold q * 0x87 once more.
	MOVQ DX, R12
	SHRQ $63, R12
	MOVQ DX, R13
	SHRQ $62, R13
	XORQ R13, R12
	MOVQ DX, R13
	SHRQ $57, R13
	XORQ R13, R12 // q
	MOVQ R12, R13
	MOVQ R12, R14
	SHLQ $1, R14
	XORQ R14, R13
	MOVQ R12, R14
	SHLQ $2, R14
	XORQ R14, R13
	SHLQ $7, R12
	XORQ R12, R13

	XORQ R8, AX
	XORQ R13, AX
	XORQ R10, BX
	MOVQ BX, zHi+32(FP)
	MOVQ AX, zLo+40(FP)
	RET
