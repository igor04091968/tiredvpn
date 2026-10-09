package gost341194

import (
	"crypto/pbkdf2"
	"testing"
)

var benchPBKDFOut []byte

func BenchmarkPBKDF2(b *testing.B) {
	for _, iter := range []struct {
		name string
		n    int
	}{
		{"1", 1},
		{"1024", 1024},
	} {
		b.Run(iter.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var err error
				benchPBKDFOut, err = pbkdf2.Key(PBKDF2Hash, "password", []byte("salt"), iter.n, 32)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
