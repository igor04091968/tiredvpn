package shipovnik

import (
	"strconv"
	"testing"
)

type benchmarkEntropyReader struct{}

func (benchmarkEntropyReader) Read(dst []byte) (int, error) {
	for i := range dst {
		dst[i] = 0xff
	}
	return len(dst), nil
}

func BenchmarkGenerateKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := Reference().GenerateKey(newDeterministicReader("benchmark-keygen")); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSign(b *testing.B) {
	private := fixedPrivateKey(b, Reference())
	message := []byte("Shipovnik benchmark message")
	for _, workers := range []int{1, 0} {
		b.Run(workerName(workers), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := private.SignMessage(newDeterministicReader("benchmark-sign"), message, &Options{Workers: workers}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkSignPreallocated(b *testing.B) {
	private := fixedPrivateKey(b, Reference())
	message := []byte("Shipovnik preallocated benchmark message")
	for _, workers := range []int{1, 0} {
		b.Run(workerName(workers), func(b *testing.B) {
			buffer := make([]byte, 0, Reference().MaxSignatureSize())
			var signature []byte
			var err error
			// Warm the pools and determine the stable signature length before the
			// allocation counters and timer start.
			signature, err = private.SignMessageTo(buffer, benchmarkEntropyReader{}, message, &Options{Workers: workers})
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(signature)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				signature, err = private.SignMessageTo(signature[:0], benchmarkEntropyReader{}, message, &Options{Workers: workers})
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkSignWorkerSweep(b *testing.B) {
	private := fixedPrivateKey(b, Reference())
	message := []byte("Shipovnik worker sweep")
	for _, workers := range []int{1, 2, 4, 6, 8, 12, 16} {
		b.Run(strconv.Itoa(workers), func(b *testing.B) {
			buffer := make([]byte, 0, Reference().MaxSignatureSize())
			signature, err := private.SignMessageTo(buffer, benchmarkEntropyReader{}, message, &Options{Workers: workers})
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(signature)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				signature, err = private.SignMessageTo(signature[:0], benchmarkEntropyReader{}, message, &Options{Workers: workers})
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkVerify(b *testing.B) {
	fixture := articleFixture(b)
	for _, workers := range []int{1, 0} {
		b.Run(workerName(workers), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				valid, err := fixture.public.Verify(fixture.message, fixture.signature, &Options{Workers: workers})
				if err != nil || !valid {
					b.Fatalf("valid=%v err=%v", valid, err)
				}
			}
		})
	}
}

func BenchmarkVerifyWorkerSweep(b *testing.B) {
	fixture := articleFixture(b)
	for _, workers := range []int{1, 2, 4, 6, 8, 10, 12, 16} {
		b.Run(strconv.Itoa(workers), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				valid, err := fixture.public.Verify(fixture.message, fixture.signature, &Options{Workers: workers})
				if err != nil || !valid {
					b.Fatalf("valid=%v err=%v", valid, err)
				}
			}
		})
	}
}

func BenchmarkVerifyParallel(b *testing.B) {
	fixture := articleFixture(b)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			valid, err := fixture.public.Verify(fixture.message, fixture.signature, nil)
			if err != nil || !valid {
				b.Errorf("valid=%v err=%v", valid, err)
				return
			}
		}
	})
}

func BenchmarkSignParallel(b *testing.B) {
	private := fixedPrivateKey(b, Article70())
	message := []byte("Shipovnik parallel benchmark message")
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := private.SignMessage(benchmarkEntropyReader{}, message, nil); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

func BenchmarkPermutation(b *testing.B) {
	permutation := make([]uint16, CodeLength)
	for i := range permutation {
		permutation[i] = uint16(CodeLength - 1 - i)
	}
	packed := make([]byte, permutationPackedSize)
	packPermutation(packed, permutation)
	var vector, output [PrivateKeySize]byte
	_, _ = newDeterministicReader("benchmark-permutation").Read(vector[:])
	b.Run("validate", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if err := validatePackedPermutation(packed); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("validate-marks", func(b *testing.B) {
		var marks [CodeLength]uint16
		var generation uint16
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			generation++
			if generation == 0 {
				clear(marks[:])
				generation = 1
			}
			if err := validatePackedPermutationWithMarks(packed, marks[:], generation); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("apply", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			applyPermutation(output[:], permutation, vector[:])
		}
	})
	b.Run("apply-packed", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			applyPackedPermutation(output[:], packed, vector[:])
		}
	})
}

func BenchmarkChallengeMapping(b *testing.B) {
	var hash [hashSize]byte
	_, _ = newDeterministicReader("benchmark-challenge").Read(hash[:])
	var trits [maxRounds]byte
	for _, scheme := range []Scheme{Reference(), Article70()} {
		b.Run(scheme.String(), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				challengeTritsTo(trits[:], scheme, hash)
			}
		})
	}
}

func BenchmarkHashPrimitives(b *testing.B) {
	first := make([]byte, permutationPackedSize)
	second := make([]byte, PublicKeySize)
	one := make([]byte, PrivateKeySize)
	b.Run("one", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = hashOne(one)
		}
	})
	b.Run("pair", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = hashPair(first, second)
		}
	})
}

func BenchmarkSyndromeGeneric(b *testing.B) {
	var vector [PrivateKeySize]byte
	_, _ = newDeterministicReader("benchmark-syndrome").Read(vector[:])
	var out [PublicKeySize]byte
	b.ReportAllocs()
	b.SetBytes(matrixSize)
	for i := 0; i < b.N; i++ {
		syndromeGeneric(out[:], vector[:])
	}
}

func BenchmarkSyndromeSelected(b *testing.B) {
	var vector [PrivateKeySize]byte
	_, _ = newDeterministicReader("benchmark-syndrome").Read(vector[:])
	var out [PublicKeySize]byte
	b.ReportAllocs()
	b.SetBytes(matrixSize)
	for i := 0; i < b.N; i++ {
		syndrome(out[:], vector[:])
	}
}

func workerName(workers int) string {
	if workers == 0 {
		return "auto"
	}
	return "serial"
}
