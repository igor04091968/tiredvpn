//go:build amd64 && !purego

package shipovnik

type syndromeBackend uint8

const (
	syndromeBackendSSE2 syndromeBackend = iota
	syndromeBackendSSE2POPCNT
	syndromeBackendAVX2
)

type amd64Features struct {
	popcnt  bool
	sse42   bool
	avx     bool
	osxsave bool
	avx2    bool
	xmmYMM  bool
}

type syndromeFunc func(out, vector []byte)

var selectedSyndromeBackend, syndromeImpl = initSyndromeBackend()

func syndrome(out, vector []byte) {
	syndromeImpl(out, vector)
}

//go:noescape
func syndromeAVX2(out, vector, matrix *byte)

//go:noescape
func syndromeSSE2POPCNT(out, vector, matrix *byte)

//go:noescape
func syndromeSSE2(out, vector, matrix *byte)

func cpuid(eaxArg, ecxArg uint32) (eax, ebx, ecx, edx uint32)
func xgetbv(index uint32) (eax, edx uint32)

func initSyndromeBackend() (syndromeBackend, syndromeFunc) {
	backend := selectSyndromeBackend(detectAMD64Features())
	switch backend {
	case syndromeBackendAVX2:
		return backend, func(out, vector []byte) {
			syndromeAVX2(&out[0], &vector[0], &hPrime[0])
		}
	case syndromeBackendSSE2POPCNT:
		return backend, func(out, vector []byte) {
			syndromeSSE2POPCNT(&out[0], &vector[0], &hPrime[0])
		}
	default:
		return backend, func(out, vector []byte) {
			syndromeSSE2(&out[0], &vector[0], &hPrime[0])
		}
	}
}

func selectSyndromeBackend(features amd64Features) syndromeBackend {
	if features.popcnt && features.avx && features.osxsave &&
		features.avx2 && features.xmmYMM {
		return syndromeBackendAVX2
	}
	if features.popcnt {
		return syndromeBackendSSE2POPCNT
	}
	return syndromeBackendSSE2
}

func detectAMD64Features() amd64Features {
	maxLeaf, _, _, _ := cpuid(0, 0)
	if maxLeaf < 1 {
		return amd64Features{}
	}
	_, _, ecx, _ := cpuid(1, 0)
	features := amd64Features{
		popcnt:  ecx&(1<<23) != 0,
		sse42:   ecx&(1<<20) != 0,
		avx:     ecx&(1<<28) != 0,
		osxsave: ecx&(1<<27) != 0,
	}
	if features.avx && features.osxsave {
		xcr0Lo, _ := xgetbv(0)
		features.xmmYMM = xcr0Lo&0x06 == 0x06
	}
	if maxLeaf >= 7 {
		_, ebx, _, _ := cpuid(7, 0)
		features.avx2 = ebx&(1<<5) != 0
	}
	return features
}

func hasAVX2() bool {
	return selectSyndromeBackend(detectAMD64Features()) == syndromeBackendAVX2
}
