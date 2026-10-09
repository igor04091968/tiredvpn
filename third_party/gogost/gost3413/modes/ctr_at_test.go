package modes_test

import (
	"bytes"
	"testing"

	"gitverse.ru/uzer_007/gogost/v3/gost3413/modes"
)

func TestCTRACPKMAtAcrossSections(t *testing.T) {
	key := bytes.Repeat([]byte{0x51}, 32)
	for _, magma := range []bool{false, true} {
		var whole, chunks *modes.CTRACPKM
		var err error
		if magma {
			cipher, e := modes.NewMagma(key)
			if e != nil {
				t.Fatal(e)
			}
			whole, err = cipher.CTRACPKM([]byte{1, 2, 3, 4}, 8<<10)
			if err == nil {
				chunks, err = cipher.CTRACPKM([]byte{1, 2, 3, 4}, 8<<10)
			}
		} else {
			cipher, e := modes.NewKuznechik(key)
			if e != nil {
				t.Fatal(e)
			}
			whole, err = cipher.CTRACPKM([]byte{1, 2, 3, 4, 5, 6, 7, 8}, 256<<10)
			if err == nil {
				chunks, err = cipher.CTRACPKM([]byte{1, 2, 3, 4, 5, 6, 7, 8}, 256<<10)
			}
		}
		if err != nil {
			t.Fatal(err)
		}
		defer whole.Close()
		defer chunks.Close()
		plain := bytes.Repeat([]byte("unaligned CTR-ACPKM chunks"), 22000)
		want, err := whole.Encrypt(nil, plain)
		if err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(plain))
		for off := 0; off < len(plain); {
			n := min(1031, len(plain)-off)
			if _, err := chunks.XORKeyStreamAt(got[off:off+n], plain[off:off+n], off); err != nil {
				t.Fatal(err)
			}
			off += n
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("offset chunks mismatch, magma=%v", magma)
		}
		if _, err := chunks.XORKeyStreamAt(got[:1], plain[:1], -1); err == nil {
			t.Fatal("negative offset accepted")
		}
	}
}
