package shipovnik

import (
	"crypto/subtle"
	"encoding/binary"
	"math/bits"
	"unsafe"
)

func setBit(vector []byte, bit int) {
	vector[bit>>3] |= 1 << (7 - uint(bit&7))
}

func packPermutation(dst []byte, permutation []uint16) {
	for i, j := 0, 0; i < CodeLength; i, j = i+2, j+3 {
		a, b := permutation[i], permutation[i+1]
		dst[j] = byte(a >> 4)
		dst[j+1] = byte(a<<4) | byte(b>>8)
		dst[j+2] = byte(b)
	}
}

func unpackPermutation(dst []uint16, packed []byte) {
	for i, j := 0, 0; i < permutationPackedSize; i, j = i+3, j+2 {
		dst[j] = uint16(packed[i])<<4 | uint16(packed[i+1]>>4)
		dst[j+1] = uint16(packed[i+1]&15)<<8 | uint16(packed[i+2])
	}
}

func validatePackedPermutation(packed []byte) error {
	if len(packed) != permutationPackedSize {
		return invalidSignaturef("invalid permutation size")
	}
	var seen [(CodeLength + 63) / 64]uint64
	for i := 0; i < permutationPackedSize; i += 3 {
		first := uint16(packed[i])<<4 | uint16(packed[i+1]>>4)
		second := uint16(packed[i+1]&15)<<8 | uint16(packed[i+2])
		if first >= CodeLength {
			return invalidSignaturef("permutation index %d is out of range", first)
		}
		if second >= CodeLength {
			return invalidSignaturef("permutation index %d is out of range", second)
		}
		firstWord, firstBit := first>>6, uint(first&63)
		firstMask := uint64(1) << firstBit
		if seen[firstWord]&firstMask != 0 {
			return invalidSignaturef("permutation contains duplicate index %d", first)
		}
		seen[firstWord] |= firstMask
		secondWord, secondBit := second>>6, uint(second&63)
		secondMask := uint64(1) << secondBit
		if seen[secondWord]&secondMask != 0 {
			return invalidSignaturef("permutation contains duplicate index %d", second)
		}
		seen[secondWord] |= secondMask
	}
	return nil
}

// validatePackedPermutationWithMarks reuses a generation-stamped table owned
// by one worker. It avoids clearing a bitmap and replaces shifts plus masks
// with direct 16-bit marker accesses. generation must be non-zero.
func validatePackedPermutationWithMarks(packed []byte, marks []uint16, generation uint16) error {
	if len(packed) != permutationPackedSize || len(marks) != CodeLength || generation == 0 {
		return invalidSignaturef("invalid permutation validation state")
	}
	_ = packed[permutationPackedSize-1]
	_ = marks[CodeLength-1]
	for i := 0; i < permutationPackedSize; i += 3 {
		first := uint16(packed[i])<<4 | uint16(packed[i+1]>>4)
		second := uint16(packed[i+1]&15)<<8 | uint16(packed[i+2])
		if first >= CodeLength {
			return invalidSignaturef("permutation index %d is out of range", first)
		}
		if second >= CodeLength {
			return invalidSignaturef("permutation index %d is out of range", second)
		}
		if marks[first] == generation {
			return invalidSignaturef("permutation contains duplicate index %d", first)
		}
		marks[first] = generation
		if marks[second] == generation {
			return invalidSignaturef("permutation contains duplicate index %d", second)
		}
		marks[second] = generation
	}
	return nil
}

// permutedBit is used only with indices generated locally or accepted by the
// strict permutation validator. Keeping that invariant at the call sites lets
// the hot gather loop avoid eight redundant slice bounds checks per byte.
func permutedBit(vector unsafe.Pointer, index uint16, outputShift uint) byte {
	value := *(*byte)(unsafe.Add(vector, uintptr(index>>3)))
	return ((value << (index & 7)) & 0x80) >> outputShift
}

func applyPermutation(dst []byte, permutation []uint16, vector []byte) {
	_ = dst[PrivateKeySize-1]
	_ = permutation[CodeLength-1]
	_ = vector[PrivateKeySize-1]
	vectorBase := unsafe.Pointer(unsafe.SliceData(vector))
	for output, index := 0, 0; output < PrivateKeySize; output, index = output+1, index+8 {
		p0, p1 := permutation[index], permutation[index+1]
		p2, p3 := permutation[index+2], permutation[index+3]
		p4, p5 := permutation[index+4], permutation[index+5]
		p6, p7 := permutation[index+6], permutation[index+7]
		dst[output] =
			permutedBit(vectorBase, p0, 0) |
				permutedBit(vectorBase, p1, 1) |
				permutedBit(vectorBase, p2, 2) |
				permutedBit(vectorBase, p3, 3) |
				permutedBit(vectorBase, p4, 4) |
				permutedBit(vectorBase, p5, 5) |
				permutedBit(vectorBase, p6, 6) |
				permutedBit(vectorBase, p7, 7)
	}
}

// applyPackedPermutation is the verification fast path. The packed input has
// already passed validatePackedPermutation, so decoding it directly avoids a
// 5.8 KiB intermediate permutation and a second traversal of that array.
func applyPackedPermutation(dst, packed, vector []byte) {
	_ = dst[PrivateKeySize-1]
	_ = packed[permutationPackedSize-1]
	_ = vector[PrivateKeySize-1]
	vectorBase := unsafe.Pointer(unsafe.SliceData(vector))
	for output, offset := 0, 0; output < PrivateKeySize; output, offset = output+1, offset+12 {
		p0 := uint16(packed[offset])<<4 | uint16(packed[offset+1]>>4)
		p1 := uint16(packed[offset+1]&15)<<8 | uint16(packed[offset+2])
		p2 := uint16(packed[offset+3])<<4 | uint16(packed[offset+4]>>4)
		p3 := uint16(packed[offset+4]&15)<<8 | uint16(packed[offset+5])
		p4 := uint16(packed[offset+6])<<4 | uint16(packed[offset+7]>>4)
		p5 := uint16(packed[offset+7]&15)<<8 | uint16(packed[offset+8])
		p6 := uint16(packed[offset+9])<<4 | uint16(packed[offset+10]>>4)
		p7 := uint16(packed[offset+10]&15)<<8 | uint16(packed[offset+11])
		dst[output] =
			permutedBit(vectorBase, p0, 0) |
				permutedBit(vectorBase, p1, 1) |
				permutedBit(vectorBase, p2, 2) |
				permutedBit(vectorBase, p3, 3) |
				permutedBit(vectorBase, p4, 4) |
				permutedBit(vectorBase, p5, 5) |
				permutedBit(vectorBase, p6, 6) |
				permutedBit(vectorBase, p7, 7)
	}
}

func xorBytes(dst, a, b []byte) {
	if len(a) < len(dst) || len(b) < len(dst) {
		panic("shipovnik: xor input is shorter than output")
	}
	subtle.XORBytes(dst, a[:len(dst)], b[:len(dst)])
}

func hammingWeight(vector []byte) int {
	weight := 0
	for len(vector) >= 8 {
		weight += bits.OnesCount64(binary.LittleEndian.Uint64(vector))
		vector = vector[8:]
	}
	for _, value := range vector {
		weight += bits.OnesCount8(value)
	}
	return weight
}
