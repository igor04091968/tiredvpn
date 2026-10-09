//go:build amd64 && !purego
// +build amd64,!purego

TEXT ·cpuid(SB), $0-24
	MOVL eaxArg+0(FP), AX
	MOVL ecxArg+4(FP), CX
	CPUID
	MOVL AX, eax+8(FP)
	MOVL BX, ebx+12(FP)
	MOVL CX, ecx+16(FP)
	MOVL DX, edx+20(FP)
	RET

TEXT ·xgetbv(SB), $0-16
	MOVL index+0(FP), CX
	XGETBV
	MOVL AX, eax+8(FP)
	MOVL DX, edx+12(FP)
	RET
