// Copyright 2026 The gogost Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

//go:build amd64 && !purego

#include "textflag.h"

// func xorWords(dst, src []uint64, n int)
TEXT ·xorWords(SB), NOSPLIT, $0-56
	MOVQ	dst_base+0(FP), AX
	MOVQ	src_base+24(FP), CX
	MOVQ	n+48(FP), DX
	SHRQ	$3, DX

xorLoop:
	MOVOU	0(AX), X0
	MOVOU	0(CX), X1
	PXOR	X1, X0
	MOVOU	X0, 0(AX)

	MOVOU	16(AX), X0
	MOVOU	16(CX), X1
	PXOR	X1, X0
	MOVOU	X0, 16(AX)

	MOVOU	32(AX), X0
	MOVOU	32(CX), X1
	PXOR	X1, X0
	MOVOU	X0, 32(AX)

	MOVOU	48(AX), X0
	MOVOU	48(CX), X1
	PXOR	X1, X0
	MOVOU	X0, 48(AX)

	ADDQ	$64, AX
	ADDQ	$64, CX
	DECQ	DX
	JNZ	xorLoop
	RET
