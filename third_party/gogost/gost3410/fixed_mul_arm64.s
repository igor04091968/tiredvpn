// Copyright 2026 The gogost Authors. All rights reserved.
// Portions adapted from Go's crypto/internal/fips140/bigmod implementation.
// Use of this source code is governed by a BSD-style license.

//go:build !purego

#include "textflag.h"

// func fixedAddMul4ARM64(z, x *uint64, y uint64) (carry uint64)
TEXT ·fixedAddMul4ARM64(SB), NOSPLIT, $0-32
	MOVD $4, R0
	JMP fixedAddMulARM64<>(SB)

// func fixedAddMul8ARM64(z, x *uint64, y uint64) (carry uint64)
TEXT ·fixedAddMul8ARM64(SB), NOSPLIT, $0-32
	MOVD $8, R0
	JMP fixedAddMulARM64<>(SB)

TEXT fixedAddMulARM64<>(SB), NOFRAME|NOSPLIT, $0
	MOVD z+0(FP), R1
	MOVD x+8(FP), R2
	MOVD y+16(FP), R3
	MOVD $0, R4

loop:
	CBZ R0, done
	LDP.P 16(R2), (R5, R6)
	LDP.P 16(R2), (R7, R8)
	LDP (R1), (R9, R10)
	ADDS R4, R9
	MUL R6, R3, R14
	ADCS R14, R10
	MUL R7, R3, R15
	LDP 16(R1), (R11, R12)
	ADCS R15, R11
	MUL R8, R3, R16
	ADCS R16, R12
	UMULH R8, R3, R20
	ADC $0, R20
	MUL R5, R3, R13
	ADDS R13, R9
	UMULH R5, R3, R17
	ADCS R17, R10
	UMULH R6, R3, R21
	STP.P (R9, R10), 16(R1)
	ADCS R21, R11
	UMULH R7, R3, R19
	ADCS R19, R12
	STP.P (R11, R12), 16(R1)
	ADC $0, R20, R4
	SUB $4, R0
	B loop

done:
	MOVD R4, carry+24(FP)
	RET
