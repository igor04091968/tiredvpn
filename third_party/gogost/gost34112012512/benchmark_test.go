package gost34112012512

import "testing"

var bench512Digest []byte

func bench512Data(n int) []byte {
	data := make([]byte, n)
	for i := range data {
		data[i] = byte(i*31 + 17)
	}
	return data
}

func BenchmarkHashMatrix(b *testing.B) {
	for _, size := range []struct {
		name string
		n    int
	}{
		{"16B", 16},
		{"64B", 64},
		{"1KiB", 1024},
		{"16KiB", 16 * 1024},
		{"1MiB", 1 << 20},
	} {
		data := bench512Data(size.n)
		h := New()
		b.Run(size.name, func(b *testing.B) {
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				h.Reset()
				if _, err := h.Write(data); err != nil {
					b.Fatal(err)
				}
				bench512Digest = h.Sum(bench512Digest[:0])
			}
		})
	}
}
