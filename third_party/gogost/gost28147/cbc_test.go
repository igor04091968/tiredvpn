package gost28147

import (
	"bytes"
	"crypto/cipher"
	"testing"
	"testing/quick"
)

func TestCBCCrypter(t *testing.T) {
	f := func(key [KeySize]byte, iv [BlockSize]byte, pt []byte) bool {
		c := NewCipher(key[:], SboxDefault)
		for i := 0; i < BlockSize; i++ {
			pt = append(pt, pt...)
		}
		ct := make([]byte, len(pt))
		e := cipher.NewCBCEncrypter(c, iv[:])
		e.CryptBlocks(ct, pt)
		d := cipher.NewCBCDecrypter(c, iv[:])
		d.CryptBlocks(ct, ct)
		return bytes.Equal(pt, ct)
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}
