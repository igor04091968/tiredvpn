package gost28147

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestWrapSymmetric(t *testing.T) {
	kek := make([]byte, KeySize)
	cek := make([]byte, KeySize)
	ukm := make([]byte, 8)
	for range 1000 {
		rand.Read(kek)
		rand.Read(cek)
		rand.Read(ukm)
		data := WrapGost(ukm, kek, cek)
		got := UnwrapGost(kek, data)
		if !bytes.Equal(got, cek) {
			t.FailNow()
		}
	}
}
