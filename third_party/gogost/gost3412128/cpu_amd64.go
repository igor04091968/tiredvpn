//go:build amd64 && !purego
// +build amd64,!purego

package gost3412128

func cpuid(eaxArg, ecxArg uint32) (eax, ebx, ecx, edx uint32)
func xgetbv(index uint32) (eax, edx uint32)

func hasAVX2() bool {
	_, _, ecx, _ := cpuid(1, 0)
	const osxsaveAVX = (1 << 27) | (1 << 28)
	if ecx&osxsaveAVX != osxsaveAVX {
		return false
	}

	xcr0Lo, _ := xgetbv(0)
	if xcr0Lo&0x06 != 0x06 {
		return false
	}

	_, ebx, _, _ := cpuid(7, 0)
	return ebx&(1<<5) != 0
}
