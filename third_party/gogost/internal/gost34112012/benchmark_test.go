package gost34112012

import "testing"

var benchStreebogDigest []byte

func benchStreebogData(n int) []byte {
	data := make([]byte, n)
	for i := range data {
		data[i] = byte(i*37 + 13)
	}
	return data
}

func BenchmarkHashMatrix(b *testing.B) {
	for _, digestSize := range []int{32, 64} {
		name := "256"
		if digestSize == 64 {
			name = "512"
		}
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
			data := benchStreebogData(size.n)
			b.Run(name+"/"+size.name, func(b *testing.B) {
				h := New(digestSize)
				b.SetBytes(int64(size.n))
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					h.Reset()
					if _, err := h.Write(data); err != nil {
						b.Fatal(err)
					}
					benchStreebogDigest = h.Sum(benchStreebogDigest[:0])
				}
			})
		}
	}
}
