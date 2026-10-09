//go:build arm64 && !purego
// +build arm64,!purego

#define ARM64_LOOKUP4_FIRST(IDX) \
		VMOV	V0.B[IDX], R7; \
		ADD		R7<<4, R4, R7; \
		VLD1	(R7), [V2.B16]; \
		VMOV	V4.B[IDX], R7; \
		ADD		R7<<4, R4, R7; \
		VLD1	(R7), [V6.B16]; \
		VMOV	V8.B[IDX], R7; \
		ADD		R7<<4, R4, R7; \
		VLD1	(R7), [V10.B16]; \
		VMOV	V12.B[IDX], R7; \
		ADD		R7<<4, R4, R7; \
		VLD1	(R7), [V14.B16]

#define ARM64_LOOKUP4_XOR(IDX) \
		VMOV	V0.B[IDX], R7; \
		ADD		R7<<4, R4, R7; \
		VLD1	(R7), [V3.B16]; \
		VEOR	V3.B16, V2.B16, V2.B16; \
		VMOV	V4.B[IDX], R7; \
		ADD		R7<<4, R4, R7; \
		VLD1	(R7), [V3.B16]; \
		VEOR	V3.B16, V6.B16, V6.B16; \
		VMOV	V8.B[IDX], R7; \
		ADD		R7<<4, R4, R7; \
		VLD1	(R7), [V3.B16]; \
		VEOR	V3.B16, V10.B16, V10.B16; \
		VMOV	V12.B[IDX], R7; \
		ADD		R7<<4, R4, R7; \
		VLD1	(R7), [V3.B16]; \
		VEOR	V3.B16, V14.B16, V14.B16

TEXT ·encryptBlockARM64(SB), $0-24
// Encrypts block.
		MOVD	dst+0(FP), R12					// Destination block.
		MOVD	src+8(FP), R2					// Plain text source block.
		VLD1	(R2), [V0.B16]					// Load PT into V0.
		MOVD	rkeys+16(FP), R3				// Load address of keys into R3.
		MOVD	·lsEncLookupPtr(SB), R4		// Load global lookup table (cipher matrix) base address (R4).
		MOVD	R4, R5							// Save R4 (matrix ref.).
		MOVD	$(1<<12), R11					// Set constant offset (0x1000; hop for lookup table rows).
		MOVD	$10, R0							// R0 will count rounds (<10).

LOOP1:	SUB		$1, R0							// Loop counter.
		CBZ		R0, BREAK

		VLD1	(R3), [V1.B16]					// Load (next) key for current round into V3.
		VEOR	V1.B16, V0.B16, V0.B16			// XOR  (PT ^ Key).
		VMOV	V0.B[0], R7						// Extract byte at index 0 from V0 (PT).
		ADD		R7<<4, R4, R7					// Compute address of lookup element. 16 bytes per record in lookup table.
		VLD1	(R7), [V2.B16]					// Load element (128 bits or 16 bytes) into V2.
		
		ADD		R11, R4							// Add offset for next row in lookup table.
		VMOV	V0.B[1], R7						// (See above.)
		ADD		R7<<4, R4, R7
		VLD1	(R7), [V4.B16]

		ADD		R11, R4
		VMOV	V0.B[2], R8
		ADD		R8<<4, R4, R8
		VLD1	(R8), [V5.B16]
		
		ADD		R11, R4
		VMOV	V0.B[3], R9
		ADD		R9<<4, R4, R9
		VLD1	(R9), [V6.B16]

		ADD		R11, R4
		VMOV	V0.B[4], R7
		ADD		R7<<4, R4, R7
		VLD1	(R7), [V7.B16]

		ADD		R11, R4
		VMOV	V0.B[5], R8
		ADD		R8<<4, R4, R8
		VLD1	(R8), [V8.B16]

		ADD		R11, R4
		VMOV	V0.B[6], R9
		ADD		R9<<4, R4, R9
		VLD1	(R9), [V9.B16]

		ADD		R11, R4
		VMOV	V0.B[7], R7
		ADD		R7<<4, R4, R7
		VLD1	(R7), [V10.B16]

		ADD		R11, R4
		VMOV	V0.B[8], R8
		ADD		R8<<4, R4, R8
		VLD1	(R8), [V11.B16]

		ADD		R11, R4
		VMOV	V0.B[9], R9
		ADD		R9<<4, R4, R9
		VLD1	(R9), [V12.B16]

		ADD		R11, R4
		VMOV	V0.B[10], R7
		ADD		R7<<4, R4, R7
		VLD1	(R7), [V13.B16]

		ADD		R11, R4
		VMOV	V0.B[11], R8
		ADD		R8<<4, R4, R8
		VLD1	(R8), [V14.B16]

		ADD		R11, R4
		VMOV	V0.B[12], R9
		ADD		R9<<4, R4, R9
		VLD1	(R9), [V15.B16]

		ADD		R11, R4
		VMOV	V0.B[13], R7
		ADD		R7<<4, R4, R7
		VLD1	(R7), [V16.B16]

		ADD		R11, R4
		VMOV	V0.B[14], R8
		ADD		R8<<4, R4, R8
		VLD1	(R8), [V17.B16]

		ADD		R11, R4
		VMOV	V0.B[15], R9
		ADD		R9<<4, R4, R9
		VLD1	(R9), [V18.B16]

		VEOR	V4.B16, V5.B16, V19.B16			// XOR every value fetched.
		VEOR	V6.B16, V7.B16, V20.B16
		VEOR	V8.B16, V9.B16, V21.B16
		VEOR	V10.B16, V11.B16, V22.B16
		VEOR	V12.B16, V13.B16, V23.B16
		VEOR	V14.B16, V15.B16, V24.B16
		VEOR	V16.B16, V17.B16, V25.B16
		VEOR	V18.B16, V2.B16, V2.B16
		VEOR	V19.B16, V2.B16, V2.B16
		VEOR	V20.B16, V2.B16, V2.B16
		VEOR	V21.B16, V2.B16, V2.B16
		VEOR	V22.B16, V2.B16, V2.B16
		VEOR	V23.B16, V2.B16, V2.B16
		VEOR	V24.B16, V2.B16, V2.B16
		VEOR	V25.B16, V2.B16, V0.B16

		ADD		$16, R3							// Next key address.
		MOVD	R5, R4							// Restore table index.
		B LOOP1
		//SUB		$1, R0							// Loop counter.
		//CBNZ	R0, LOOP1						// Loop if we have to.
		
BREAK:	VLD1	(R3), [V1.B16]
		VEOR	V1.B16, V0.B16, V0.B16			// XOR with last key.
	
		VST1	[V0.B16], (R12)					// Store result.
		
		RET


TEXT ·xorKeyStreamARM64Blocks(SB), $16-40
// Counter mode for full blocks. The Go wrapper handles the tail.
		MOVD	buf+0(FP), R12
		MOVD	buf_len+8(FP), R13
		LSR		$4, R13
		CBZ		R13, CMARM64_DONE

		MOVD	iv+24(FP), R6
		MOVD	R6, R14
		REV		R14, R14
		MOVD	rkeys+32(FP), R10

CMARM64_BLOCK:
		MOVD	R6, R7
		REV		R7, R7
		MOVD	R7, 0(RSP)
		MOVD	R14, 8(RSP)
		VLD1	(RSP), [V0.B16]
		VLD1	(R12), [V5.B16]

		MOVD	R10, R3
		MOVD	·lsEncLookupPtr(SB), R4
		MOVD	R4, R5
		MOVD	$(1<<12), R11
		MOVD	$9, R0

CMARM64_ENC:
		VLD1	(R3), [V1.B16]
		VEOR	V1.B16, V0.B16, V0.B16
		VMOV	V0.B[0], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V2.B16]

		ADD		R11, R4
		VMOV	V0.B[1], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[2], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[3], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[4], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[5], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[6], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[7], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[8], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[9], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[10], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[11], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[12], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[13], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[14], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[15], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		$16, R3
		VMOV	V2.B16, V0.B16
		MOVD	R5, R4

		SUB		$1, R0
		CBNZ	R0, CMARM64_ENC

		VLD1	(R3), [V1.B16]
		VEOR	V1.B16, V0.B16, V0.B16
		VEOR	V0.B16, V5.B16, V5.B16
		VST1	[V5.B16], (R12)

		ADD		$16, R12
		ADD		$1, R6
		SUB		$1, R13
		CBNZ	R13, CMARM64_BLOCK

CMARM64_DONE:
		RET

TEXT ·xorKeyStreamARM64Blocks4(SB), $64-40
		MOVD	buf+0(FP), R12
		MOVD	buf_len+8(FP), R13
		LSR		$6, R13
		CBZ		R13, CMARM64_4_DONE

		MOVD	iv+24(FP), R6
		MOVD	R6, R14
		REV		R14, R14
		MOVD	rkeys+32(FP), R10

CMARM64_4_BLOCK:
		MOVD	R6, R7
		REV		R7, R7
		MOVD	R7, 0(RSP)
		MOVD	R14, 8(RSP)
		MOVD	R6, R7
		ADD		$1, R7
		REV		R7, R7
		MOVD	R7, 16(RSP)
		MOVD	R14, 24(RSP)
		MOVD	R6, R7
		ADD		$2, R7
		REV		R7, R7
		MOVD	R7, 32(RSP)
		MOVD	R14, 40(RSP)
		MOVD	R6, R7
		ADD		$3, R7
		REV		R7, R7
		MOVD	R7, 48(RSP)
		MOVD	R14, 56(RSP)

		VLD1	(RSP), [V0.B16]
		ADD		$16, RSP, R2
		VLD1	(R2), [V4.B16]
		ADD		$32, RSP, R2
		VLD1	(R2), [V8.B16]
		ADD		$48, RSP, R2
		VLD1	(R2), [V12.B16]

		VLD1	(R12), [V5.B16]
		ADD		$16, R12, R2
		VLD1	(R2), [V9.B16]
		ADD		$32, R12, R2
		VLD1	(R2), [V13.B16]
		ADD		$48, R12, R2
		VLD1	(R2), [V15.B16]

		MOVD	R10, R3
		MOVD	·lsEncLookupPtr(SB), R4
		MOVD	R4, R5
		MOVD	$(1<<12), R11
		MOVD	$9, R0

CMARM64_4_ENC:
		VLD1	(R3), [V1.B16]
		VEOR	V1.B16, V0.B16, V0.B16
		VEOR	V1.B16, V4.B16, V4.B16
		VEOR	V1.B16, V8.B16, V8.B16
		VEOR	V1.B16, V12.B16, V12.B16

		ARM64_LOOKUP4_FIRST(0)
		ADD		R11, R4
		ARM64_LOOKUP4_XOR(1)
		ADD		R11, R4
		ARM64_LOOKUP4_XOR(2)
		ADD		R11, R4
		ARM64_LOOKUP4_XOR(3)
		ADD		R11, R4
		ARM64_LOOKUP4_XOR(4)
		ADD		R11, R4
		ARM64_LOOKUP4_XOR(5)
		ADD		R11, R4
		ARM64_LOOKUP4_XOR(6)
		ADD		R11, R4
		ARM64_LOOKUP4_XOR(7)
		ADD		R11, R4
		ARM64_LOOKUP4_XOR(8)
		ADD		R11, R4
		ARM64_LOOKUP4_XOR(9)
		ADD		R11, R4
		ARM64_LOOKUP4_XOR(10)
		ADD		R11, R4
		ARM64_LOOKUP4_XOR(11)
		ADD		R11, R4
		ARM64_LOOKUP4_XOR(12)
		ADD		R11, R4
		ARM64_LOOKUP4_XOR(13)
		ADD		R11, R4
		ARM64_LOOKUP4_XOR(14)
		ADD		R11, R4
		ARM64_LOOKUP4_XOR(15)

		ADD		$16, R3
		VMOV	V2.B16, V0.B16
		VMOV	V6.B16, V4.B16
		VMOV	V10.B16, V8.B16
		VMOV	V14.B16, V12.B16
		MOVD	R5, R4

		SUB		$1, R0
		CBNZ	R0, CMARM64_4_ENC

		VLD1	(R3), [V1.B16]
		VEOR	V1.B16, V0.B16, V0.B16
		VEOR	V1.B16, V4.B16, V4.B16
		VEOR	V1.B16, V8.B16, V8.B16
		VEOR	V1.B16, V12.B16, V12.B16
		VEOR	V0.B16, V5.B16, V5.B16
		VEOR	V4.B16, V9.B16, V9.B16
		VEOR	V8.B16, V13.B16, V13.B16
		VEOR	V12.B16, V15.B16, V15.B16

		VST1	[V5.B16], (R12)
		ADD		$16, R12, R2
		VST1	[V9.B16], (R2)
		ADD		$32, R12, R2
		VST1	[V13.B16], (R2)
		ADD		$48, R12, R2
		VST1	[V15.B16], (R2)

		ADD		$64, R12
		ADD		$4, R6
		SUB		$1, R13
		CBNZ	R13, CMARM64_4_BLOCK

CMARM64_4_DONE:
		RET

TEXT ·decryptBlockARM64(SB), $0-24
// Decryption. Less optimized.
		MOVD	dst+0(FP), R12					// Destination block.
		MOVD	src+8(FP), R2					// Cipher text source block.
		VLD1	(R2), [V0.B16]
		MOVD	·lInvLookupPtr(SB), R4		// Load global lookup table base address.
		MOVD	$(1<<12), R11
		
		VMOV	V0.B[0], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V2.B16]
		
		ADD		R11, R4
		VMOV	V0.B[1], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16
		
		ADD		R11, R4
		VMOV	V0.B[2], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16
		
		ADD		R11, R4
		VMOV	V0.B[3], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[4], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[5], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[6], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[7], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[8], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[9], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[10], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[11], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16
		
		ADD		R11, R4
		VMOV	V0.B[12], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[13], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[14], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[15], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16
		VMOV	V2.B16, V0.B16

		MOVD	·slDecLookupPtr(SB), R4		// Load global lookup table (cipher matrix) base address (R4).
		MOVD	R4, R5							// Save R4 (matrix ref.).
		MOVD	$8, R0							// R0 will count rounds.

		MOVD	rkeys+16(FP), R3
		ADD		$144, R3						// We want last key here.

LOOP3:	VLD1	(R3), [V1.B16]					// Round key.
		VEOR	V1.B16, V0.B16, V0.B16
		VMOV	V0.B[0], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V2.B16]
		
		ADD		R11, R4
		VMOV	V0.B[1], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[2], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16
		
		ADD		R11, R4
		VMOV	V0.B[3], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[4], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[5], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[6], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[7], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[8], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[9], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[10], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[11], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[12], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[13], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[14], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[15], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		SUB		$16, R3
		VMOV	V2.B16, V0.B16
		MOVD	R5, R4

		SUB		$1, R0
		CBNZ	R0, LOOP3
		
		VLD1	(R3), [V1.B16]
		VEOR	V1.B16, V0.B16, V0.B16
		SUB		$16, R3
		
		MOVD	·piInverseTablePtr(SB), R4
		
		VMOV	V0.B[0], R7
		ADD		R4, R7
		VLD1	(R7), V2.B[0]

		VMOV	V0.B[1], R7
		ADD		R4, R7
		VLD1	(R7), V2.B[1]

		VMOV	V0.B[2], R7
		ADD		R4, R7
		VLD1	(R7), V2.B[2]

		VMOV	V0.B[3], R7
		ADD		R4, R7
		VLD1	(R7), V2.B[3]

		VMOV	V0.B[4], R7
		ADD		R4, R7
		VLD1	(R7), V2.B[4]
		
		VMOV	V0.B[5], R7
		ADD		R4, R7
		VLD1	(R7), V2.B[5]

		VMOV	V0.B[6], R7
		ADD		R4, R7
		VLD1	(R7), V2.B[6]

		VMOV	V0.B[7], R7
		ADD		R4, R7
		VLD1	(R7), V2.B[7]

		VMOV	V0.B[8], R7
		ADD		R4, R7
		VLD1	(R7), V2.B[8]

		VMOV	V0.B[9], R7
		ADD		R4, R7
		VLD1	(R7), V2.B[9]

		VMOV	V0.B[10], R7
		ADD		R4, R7
		VLD1	(R7), V2.B[10]

		VMOV	V0.B[11], R7
		ADD		R4, R7
		VLD1	(R7), V2.B[11]

		VMOV	V0.B[12], R7
		ADD		R4, R7
		VLD1	(R7), V2.B[12]

		VMOV	V0.B[13], R7
		ADD		R4, R7
		VLD1	(R7), V2.B[13]

		VMOV	V0.B[14], R7
		ADD		R4, R7
		VLD1	(R7), V2.B[14]

		VMOV	V0.B[15], R7
		ADD		R4, R7
		VLD1	(R7), V2.B[15]
	
		VLD1	(R3), [V1.B16]
		VEOR	V1.B16, V2.B16, V2.B16
		
		VST1	[V2.B16], (R12)
	
		RET

