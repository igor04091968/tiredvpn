// Copyright 2026 The gogost Authors. All rights reserved.
// Portions adapted from Go's crypto/internal/fips140/bigmod implementation.
// Use of this source code is governed by a BSD-style license.

//go:build !purego

#include "textflag.h"

// func fixedAddMul4ADX(z, x *uint64, y uint64) (carry uint64)
// Requires ADX and BMI2. Dispatch is performed once while constructing the
// immutable field domain.
TEXT ·fixedAddMul4ADX(SB), NOSPLIT, $0-32
	MOVQ z+0(FP), AX
	MOVQ x+8(FP), CX
	MOVQ y+16(FP), DX
	XORQ BX, BX
	XORQ SI, SI

	MULXQ 0(CX), R8, DI
	ADCXQ BX, R8
	ADOXQ 0(AX), R8
	MOVQ R8, 0(AX)

	MULXQ 8(CX), R8, BX
	ADCXQ DI, R8
	ADOXQ 8(AX), R8
	MOVQ R8, 8(AX)

	MULXQ 16(CX), R8, DI
	ADCXQ BX, R8
	ADOXQ 16(AX), R8
	MOVQ R8, 16(AX)

	MULXQ 24(CX), R8, BX
	ADCXQ DI, R8
	ADOXQ 24(AX), R8
	MOVQ R8, 24(AX)

	ADCXQ SI, BX
	ADOXQ SI, BX
	MOVQ BX, carry+24(FP)
	RET

// func fixedAddMul8ADX(z, x *uint64, y uint64) (carry uint64)
TEXT ·fixedAddMul8ADX(SB), NOSPLIT, $0-32
	MOVQ z+0(FP), AX
	MOVQ x+8(FP), CX
	MOVQ y+16(FP), DX
	XORQ BX, BX
	XORQ SI, SI

	MULXQ 0(CX), R8, DI
	ADCXQ BX, R8
	ADOXQ 0(AX), R8
	MOVQ R8, 0(AX)
	MULXQ 8(CX), R8, BX
	ADCXQ DI, R8
	ADOXQ 8(AX), R8
	MOVQ R8, 8(AX)
	MULXQ 16(CX), R8, DI
	ADCXQ BX, R8
	ADOXQ 16(AX), R8
	MOVQ R8, 16(AX)
	MULXQ 24(CX), R8, BX
	ADCXQ DI, R8
	ADOXQ 24(AX), R8
	MOVQ R8, 24(AX)
	MULXQ 32(CX), R8, DI
	ADCXQ BX, R8
	ADOXQ 32(AX), R8
	MOVQ R8, 32(AX)
	MULXQ 40(CX), R8, BX
	ADCXQ DI, R8
	ADOXQ 40(AX), R8
	MOVQ R8, 40(AX)
	MULXQ 48(CX), R8, DI
	ADCXQ BX, R8
	ADOXQ 48(AX), R8
	MOVQ R8, 48(AX)
	MULXQ 56(CX), R8, BX
	ADCXQ DI, R8
	ADOXQ 56(AX), R8
	MOVQ R8, 56(AX)

	ADCXQ SI, BX
	ADOXQ SI, BX
	MOVQ BX, carry+24(FP)
	RET
