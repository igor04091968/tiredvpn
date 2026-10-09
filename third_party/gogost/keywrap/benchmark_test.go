package keywrap

import "testing"

var (
	benchWrapped []byte
	benchCEK     []byte
)

func benchWrapBytes(n int) []byte {
	data := make([]byte, n)
	for i := range data {
		data[i] = byte(i*13 + 7)
	}
	return data
}

func BenchmarkWrapUnwrap(b *testing.B) {
	kek := benchWrapBytes(CEKSize)
	cek := benchWrapBytes(CEKSize)
	ukm := benchWrapBytes(UKMSize)
	for _, tc := range []struct {
		name string
		alg  Algorithm
	}{
		{"Gost28147", AlgorithmGost28147},
		{"CryptoPro", AlgorithmCryptoPro},
		{"Magma", AlgorithmMagma},
		{"Kuznechik", AlgorithmKuznechik},
	} {
		wrapped, err := Wrap(nil, cek, Config{Algorithm: tc.alg, KEK: kek, UKM: ukm})
		if err != nil {
			b.Fatal(err)
		}
		b.Run(tc.name+"/Wrap", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				benchWrapped, err = Wrap(benchWrapped[:0], cek, Config{
					Algorithm: tc.alg,
					KEK:       kek,
					UKM:       ukm,
				})
				if err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(tc.name+"/Unwrap", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				benchCEK, err = Unwrap(benchCEK[:0], wrapped, Config{
					Algorithm: tc.alg,
					KEK:       kek,
				})
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
