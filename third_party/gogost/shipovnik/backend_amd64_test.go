//go:build amd64 && !purego

package shipovnik

import (
	"bytes"
	"testing"
)

func TestSyndromeBackendSelection(t *testing.T) {
	tests := []struct {
		name     string
		features amd64Features
		want     syndromeBackend
	}{
		{name: "baseline", want: syndromeBackendSSE2},
		{name: "sse42-only", features: amd64Features{sse42: true}, want: syndromeBackendSSE2},
		{name: "popcnt", features: amd64Features{popcnt: true}, want: syndromeBackendSSE2POPCNT},
		{name: "sse42-popcnt", features: amd64Features{sse42: true, popcnt: true}, want: syndromeBackendSSE2POPCNT},
		{
			name: "avx2",
			features: amd64Features{
				popcnt: true, avx: true, osxsave: true, avx2: true, xmmYMM: true,
			},
			want: syndromeBackendAVX2,
		},
		{
			name: "avx2-no-popcnt",
			features: amd64Features{
				avx: true, osxsave: true, avx2: true, xmmYMM: true,
			},
			want: syndromeBackendSSE2,
		},
		{
			name: "avx2-no-os-state",
			features: amd64Features{
				popcnt: true, avx: true, osxsave: true, avx2: true,
			},
			want: syndromeBackendSSE2POPCNT,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := selectSyndromeBackend(test.features); got != test.want {
				t.Fatalf("backend = %d, want %d", got, test.want)
			}
		})
	}

	if want := selectSyndromeBackend(detectAMD64Features()); selectedSyndromeBackend != want {
		t.Fatalf("selected backend = %d, want %d", selectedSyndromeBackend, want)
	}
}

func TestSyndromeAMD64BackendsDifferential(t *testing.T) {
	features := detectAMD64Features()
	for test := 0; test < 16; test++ {
		var vector [PrivateKeySize]byte
		reader := newDeterministicReader(string(rune(test + 1)))
		if _, err := reader.Read(vector[:]); err != nil {
			t.Fatal(err)
		}
		var generic, got [PublicKeySize]byte
		syndromeGeneric(generic[:], vector[:])

		syndromeSSE2(&got[0], &vector[0], &hPrime[0])
		if !bytes.Equal(generic[:], got[:]) {
			t.Fatalf("test %d: SSE2 syndrome mismatch", test)
		}

		if features.popcnt {
			clear(got[:])
			syndromeSSE2POPCNT(&got[0], &vector[0], &hPrime[0])
			if !bytes.Equal(generic[:], got[:]) {
				t.Fatalf("test %d: SSE2+POPCNT syndrome mismatch", test)
			}
		}

		if features.popcnt && features.avx && features.osxsave && features.avx2 && features.xmmYMM {
			clear(got[:])
			syndromeAVX2(&got[0], &vector[0], &hPrime[0])
			if !bytes.Equal(generic[:], got[:]) {
				t.Fatalf("test %d: AVX2 syndrome mismatch", test)
			}
		}
	}
}

func BenchmarkSyndromeSSE2(b *testing.B) {
	benchmarkSyndromeAMD64(b, syndromeSSE2)
}

func BenchmarkSyndromeSSE2POPCNT(b *testing.B) {
	if !detectAMD64Features().popcnt {
		b.Skip("POPCNT unavailable")
	}
	benchmarkSyndromeAMD64(b, syndromeSSE2POPCNT)
}

func BenchmarkSyndromeAVX2(b *testing.B) {
	if !hasAVX2() {
		b.Skip("AVX2 unavailable")
	}
	benchmarkSyndromeAMD64(b, syndromeAVX2)
}

func benchmarkSyndromeAMD64(b *testing.B, backend func(out, vector, matrix *byte)) {
	var vector [PrivateKeySize]byte
	if _, err := newDeterministicReader("benchmark-syndrome").Read(vector[:]); err != nil {
		b.Fatal(err)
	}
	var out [PublicKeySize]byte
	b.ReportAllocs()
	b.SetBytes(matrixSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		backend(&out[0], &vector[0], &hPrime[0])
	}
	if out == [PublicKeySize]byte{} {
		b.Fatal("backend produced an all-zero syndrome")
	}
}
