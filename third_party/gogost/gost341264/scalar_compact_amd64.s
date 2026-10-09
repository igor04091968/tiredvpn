//go:build amd64 && !purego

#include "textflag.h"

// Четыре строки по 256 uint32 занимают 4 КиБ. В режимах с обратной связью
// вход следующего блока зависит от предыдущего, поэтому широкую T16-таблицу
// нельзя эффективно скрыть параллелизмом независимых блоков.
#define ROUND(KEYOFF) \
	MOVL AX, CX; \
	ADDL KEYOFF(R8), CX; \
	MOVBLZX CL, DX; \
	MOVL (R9)(DX*4), SI; \
	SHRL $8, CX; \
	MOVBLZX CL, DX; \
	XORL (R10)(DX*4), SI; \
	SHRL $8, CX; \
	MOVBLZX CL, DX; \
	XORL (R11)(DX*4), SI; \
	SHRL $8, CX; \
	MOVBLZX CL, DX; \
	XORL (R12)(DX*4), SI; \
	XORL BX, SI; \
	MOVL AX, BX; \
	MOVL SI, AX

TEXT ·magmaCrypt32CompactEncrypt(SB), NOSPLIT, $0-32
	MOVQ keys+0(FP), R8
	MOVQ table+8(FP), R9
	MOVL n1+16(FP), AX
	MOVL n2+20(FP), BX
	LEAQ 1024(R9), R10
	LEAQ 2048(R9), R11
	LEAQ 3072(R9), R12
	ROUND(0)
	ROUND(4)
	ROUND(8)
	ROUND(12)
	ROUND(16)
	ROUND(20)
	ROUND(24)
	ROUND(28)
	ROUND(0)
	ROUND(4)
	ROUND(8)
	ROUND(12)
	ROUND(16)
	ROUND(20)
	ROUND(24)
	ROUND(28)
	ROUND(0)
	ROUND(4)
	ROUND(8)
	ROUND(12)
	ROUND(16)
	ROUND(20)
	ROUND(24)
	ROUND(28)
	ROUND(28)
	ROUND(24)
	ROUND(20)
	ROUND(16)
	ROUND(12)
	ROUND(8)
	ROUND(4)
	ROUND(0)
	MOVL AX, ret1+24(FP)
	MOVL BX, ret2+28(FP)
	RET

TEXT ·magmaCrypt32CompactDecrypt(SB), NOSPLIT, $0-32
	MOVQ keys+0(FP), R8
	MOVQ table+8(FP), R9
	MOVL n1+16(FP), AX
	MOVL n2+20(FP), BX
	LEAQ 1024(R9), R10
	LEAQ 2048(R9), R11
	LEAQ 3072(R9), R12
	ROUND(0)
	ROUND(4)
	ROUND(8)
	ROUND(12)
	ROUND(16)
	ROUND(20)
	ROUND(24)
	ROUND(28)
	ROUND(28)
	ROUND(24)
	ROUND(20)
	ROUND(16)
	ROUND(12)
	ROUND(8)
	ROUND(4)
	ROUND(0)
	ROUND(28)
	ROUND(24)
	ROUND(20)
	ROUND(16)
	ROUND(12)
	ROUND(8)
	ROUND(4)
	ROUND(0)
	ROUND(28)
	ROUND(24)
	ROUND(20)
	ROUND(16)
	ROUND(12)
	ROUND(8)
	ROUND(4)
	ROUND(0)
	MOVL AX, ret1+24(FP)
	MOVL BX, ret2+28(FP)
	RET
