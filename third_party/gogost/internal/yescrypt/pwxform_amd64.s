// Copyright 2026 The gogost Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

//go:build amd64 && !purego

#include "textflag.h"

// func pwxform(x *[pwxWords]uint64, ctx *pwxformCtx)
TEXT ·pwxform(SB), NOSPLIT, $0-16
	MOVQ	x+0(FP), AX
	MOVQ	ctx+8(FP), DI
	MOVQ	0(DI), BX
	MOVQ	8(DI), CX
	MOVQ	16(DI), DX
	MOVL	24(DI), R8
	XORL	R9, R9

pwxRound:
	XORL	SI, SI

pwxGather:
	MOVQ	0(AX)(SI*1), R11
	MOVQ	R11, R12
	SHRQ	$32, R11
	MOVL	R12, R13
	IMULQ	R11, R13
	ANDL	$4080, R12
	SHRL	$3, R12
	ANDL	$4080, R11
	SHRL	$3, R11
	ADDQ	0(BX)(R12*8), R13
	XORQ	0(CX)(R11*8), R13
	MOVQ	R13, 0(AX)(SI*1)

	MOVQ	8(AX)(SI*1), R15
	MOVQ	R15, R10
	SHRQ	$32, R15
	MOVL	R10, R10
	IMULQ	R15, R10
	ADDQ	8(BX)(R12*8), R10
	XORQ	8(CX)(R11*8), R10
	MOVQ	R10, 8(AX)(SI*1)

	TESTQ	R9, R9
	JEQ	pwxNoStore
	CMPQ	R9, $5
	JEQ	pwxNoStore
	MOVQ	R13, 0(DX)(R8*8)
	MOVQ	R10, 8(DX)(R8*8)
	ADDL	$2, R8

pwxNoStore:
	ADDQ	$16, SI
	CMPQ	SI, $64
	JLT	pwxGather
	INCQ	R9
	CMPQ	R9, $6
	JLT	pwxRound

	MOVQ	DX, 0(DI)
	MOVQ	BX, 8(DI)
	MOVQ	CX, 16(DI)
	ANDL	$511, R8
	MOVL	R8, 24(DI)
	RET
