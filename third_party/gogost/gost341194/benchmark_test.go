package gost341194

import "testing"

var bench341194Digest []byte

func bench341194Data(n int) []byte {
	data := make([]byte, n)
	for i := range data {
		data[i] = byte(i*41 + 9)
	}
	return data
}

func BenchmarkHashMatrix(b *testing.B) {
	for _, size := range []struct {
		name string
		n    int
	}{
		{"16B", 16},
		{"32B", 32},
		{"1KiB", 1024},
		{"16KiB", 16 * 1024},
		{"1MiB", 1 << 20},
	} {
		data := bench341194Data(size.n)
		b.Run(size.name, func(b *testing.B) {
			h := New(SboxDefault)
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				h.Reset()
				if _, err := h.Write(data); err != nil {
					b.Fatal(err)
				}
				bench341194Digest = h.Sum(bench341194Digest[:0])
			}
		})
	}
}
