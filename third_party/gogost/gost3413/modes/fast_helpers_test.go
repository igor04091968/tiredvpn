package modes_test

import (
	"bytes"
	"crypto/cipher"
	"testing"

	"gitverse.ru/uzer_007/gogost/v3/gost28147"
	"gitverse.ru/uzer_007/gogost/v3/gost3412128"
	"gitverse.ru/uzer_007/gogost/v3/gost341264"
	"gitverse.ru/uzer_007/gogost/v3/gost3413/modes"
)

type fastHelperBlock interface {
	cipher.Block
	EncryptCBC(dst, src, iv []byte)
	DecryptCBC(dst, src, iv []byte)
	EncryptCFB(dst, src, iv []byte)
	DecryptCFB(dst, src, iv []byte)
	XORKeyStreamOFB(dst, src, iv []byte)
	XORKeyStreamCTRCounter(dst, src, counter []byte)
	SumGOST3413MAC(dst, data []byte, tagSize int) []byte
	VerifyGOST3413MAC(data, tag []byte) bool
}

type onlyBlock struct {
	b cipher.Block
}

func (b onlyBlock) BlockSize() int          { return b.b.BlockSize() }
func (b onlyBlock) Encrypt(dst, src []byte) { b.b.Encrypt(dst, src) }
func (b onlyBlock) Decrypt(dst, src []byte) { b.b.Decrypt(dst, src) }

func TestFastHelpersMatchGenericModes(t *testing.T) {
	for _, tc := range []struct {
		name string
		new  func() fastHelperBlock
	}{
		{"GOST28147", func() fastHelperBlock { return gost28147.NewCipher(testKey(), gost28147.SboxDefault) }},
		{"Magma", func() fastHelperBlock { return gost341264.NewCipher(testKey()) }},
		{"Kuznechik", func() fastHelperBlock { return gost3412128.NewCipher(testKey()) }},
	} {
		block := tc.new()
		blockSize := block.BlockSize()
		iv := testIV(blockSize)
		for _, size := range []int{0, 1, blockSize - 1, blockSize, blockSize + 1, 64, 1024} {
			plaintext := testPlaintext(size)

			assertStreamHelper(t, tc.name+"/CFB", block.EncryptCFB, block.DecryptCFB, genericCFBEncrypt, genericCFBDecrypt, block, iv, plaintext)
			assertOFBHelper(t, tc.name+"/OFB", block, iv, plaintext)
			assertCTRHelper(t, tc.name+"/CTR", block, iv, plaintext)

			tag := block.SumGOST3413MAC(nil, plaintext, min(4, blockSize))
			refMAC, err := modes.NewMAC(onlyBlock{block}, min(4, blockSize))
			if err != nil {
				t.Fatal(err)
			}
			wantTag := refMAC.Sum(nil, plaintext)
			if !bytes.Equal(tag, wantTag) {
				t.Fatalf("%s/MAC/%d tag=%x want %x", tc.name, size, tag, wantTag)
			}
			if !block.VerifyGOST3413MAC(plaintext, tag) {
				t.Fatalf("%s/MAC/%d rejected valid tag", tc.name, size)
			}
			tag[0] ^= 0xff
			if block.VerifyGOST3413MAC(plaintext, tag) {
				t.Fatalf("%s/MAC/%d accepted tampered tag", tc.name, size)
			}

			if size%blockSize == 0 {
				assertCBCHelper(t, tc.name+"/CBC", block, iv, plaintext)
			}
		}
	}
}

func assertCBCHelper(t *testing.T, name string, block fastHelperBlock, iv, plaintext []byte) {
	t.Helper()
	want := make([]byte, len(plaintext))
	genericCBCEncrypt(block, want, plaintext, iv)
	got := make([]byte, len(plaintext))
	block.EncryptCBC(got, plaintext, iv)
	if !bytes.Equal(got, want) {
		t.Fatalf("%s encrypt mismatch", name)
	}
	inPlace := append([]byte(nil), plaintext...)
	block.EncryptCBC(inPlace, inPlace, iv)
	if !bytes.Equal(inPlace, want) {
		t.Fatalf("%s in-place encrypt mismatch", name)
	}

	wantPlain := make([]byte, len(plaintext))
	genericCBCDecrypt(block, wantPlain, want, iv)
	gotPlain := make([]byte, len(plaintext))
	block.DecryptCBC(gotPlain, want, iv)
	if !bytes.Equal(gotPlain, wantPlain) {
		t.Fatalf("%s decrypt mismatch", name)
	}
	copy(inPlace, want)
	block.DecryptCBC(inPlace, inPlace, iv)
	if !bytes.Equal(inPlace, plaintext) {
		t.Fatalf("%s in-place decrypt mismatch", name)
	}
}

func assertStreamHelper(
	t *testing.T,
	name string,
	encryptFast func(dst, src, iv []byte),
	decryptFast func(dst, src, iv []byte),
	encryptGeneric func(cipher.Block, []byte, []byte, []byte),
	decryptGeneric func(cipher.Block, []byte, []byte, []byte),
	block fastHelperBlock,
	iv, plaintext []byte,
) {
	t.Helper()
	want := make([]byte, len(plaintext))
	encryptGeneric(block, want, plaintext, iv)
	got := make([]byte, len(plaintext))
	encryptFast(got, plaintext, iv)
	if !bytes.Equal(got, want) {
		t.Fatalf("%s encrypt mismatch", name)
	}
	inPlace := append([]byte(nil), plaintext...)
	encryptFast(inPlace, inPlace, iv)
	if !bytes.Equal(inPlace, want) {
		t.Fatalf("%s in-place encrypt mismatch", name)
	}

	wantPlain := make([]byte, len(plaintext))
	decryptGeneric(block, wantPlain, want, iv)
	gotPlain := make([]byte, len(plaintext))
	decryptFast(gotPlain, want, iv)
	if !bytes.Equal(gotPlain, wantPlain) {
		t.Fatalf("%s decrypt mismatch", name)
	}
	copy(inPlace, want)
	decryptFast(inPlace, inPlace, iv)
	if !bytes.Equal(inPlace, plaintext) {
		t.Fatalf("%s in-place decrypt mismatch", name)
	}
}

func assertOFBHelper(t *testing.T, name string, block fastHelperBlock, iv, plaintext []byte) {
	t.Helper()
	want := make([]byte, len(plaintext))
	genericOFB(block, want, plaintext, iv)
	got := make([]byte, len(plaintext))
	block.XORKeyStreamOFB(got, plaintext, iv)
	if !bytes.Equal(got, want) {
		t.Fatalf("%s mismatch", name)
	}
	inPlace := append([]byte(nil), plaintext...)
	block.XORKeyStreamOFB(inPlace, inPlace, iv)
	if !bytes.Equal(inPlace, want) {
		t.Fatalf("%s in-place mismatch", name)
	}
}

func assertCTRHelper(t *testing.T, name string, block fastHelperBlock, iv, plaintext []byte) {
	t.Helper()
	counter := make([]byte, block.BlockSize())
	copy(counter, iv)
	wantCounter := append([]byte(nil), counter...)
	want := make([]byte, len(plaintext))
	genericCTR(block, want, plaintext, wantCounter)

	gotCounter := append([]byte(nil), counter...)
	got := make([]byte, len(plaintext))
	block.XORKeyStreamCTRCounter(got, plaintext, gotCounter)
	if !bytes.Equal(got, want) {
		t.Fatalf("%s mismatch", name)
	}
	if !bytes.Equal(gotCounter, wantCounter) {
		t.Fatalf("%s counter=%x want %x", name, gotCounter, wantCounter)
	}
	inPlace := append([]byte(nil), plaintext...)
	inPlaceCounter := append([]byte(nil), counter...)
	block.XORKeyStreamCTRCounter(inPlace, inPlace, inPlaceCounter)
	if !bytes.Equal(inPlace, want) {
		t.Fatalf("%s in-place mismatch", name)
	}
}

func genericCBCEncrypt(block cipher.Block, dst, src, iv []byte) {
	blockSize := block.BlockSize()
	prev := append([]byte(nil), iv...)
	tmp := make([]byte, blockSize)
	for len(src) >= blockSize {
		xorBytes(tmp, src[:blockSize], prev)
		block.Encrypt(dst[:blockSize], tmp)
		copy(prev, dst[:blockSize])
		dst = dst[blockSize:]
		src = src[blockSize:]
	}
}

func genericCBCDecrypt(block cipher.Block, dst, src, iv []byte) {
	blockSize := block.BlockSize()
	prev := append([]byte(nil), iv...)
	tmp := make([]byte, blockSize)
	for len(src) >= blockSize {
		copy(tmp, src[:blockSize])
		block.Decrypt(dst[:blockSize], src[:blockSize])
		xorBytes(dst[:blockSize], dst[:blockSize], prev)
		copy(prev, tmp)
		dst = dst[blockSize:]
		src = src[blockSize:]
	}
}

func genericCFBEncrypt(block cipher.Block, dst, src, iv []byte) {
	genericCFB(block, dst, src, iv, true)
}

func genericCFBDecrypt(block cipher.Block, dst, src, iv []byte) {
	genericCFB(block, dst, src, iv, false)
}

func genericCFB(block cipher.Block, dst, src, iv []byte, encrypt bool) {
	blockSize := block.BlockSize()
	register := append([]byte(nil), iv...)
	gamma := make([]byte, blockSize)
	feedback := make([]byte, blockSize)
	for len(src) > 0 {
		block.Encrypt(gamma, register)
		n := min(blockSize, len(src))
		if !encrypt {
			copy(feedback, src[:n])
		}
		xorBytes(dst[:n], src[:n], gamma[:n])
		if encrypt {
			shift(register, dst[:n])
		} else {
			shift(register, feedback[:n])
		}
		dst = dst[n:]
		src = src[n:]
	}
}

func genericOFB(block cipher.Block, dst, src, iv []byte) {
	blockSize := block.BlockSize()
	register := append([]byte(nil), iv...)
	gamma := make([]byte, blockSize)
	for len(src) > 0 {
		block.Encrypt(gamma, register)
		n := min(blockSize, len(src))
		xorBytes(dst[:n], src[:n], gamma[:n])
		shift(register, gamma[:n])
		dst = dst[n:]
		src = src[n:]
	}
}

func genericCTR(block cipher.Block, dst, src, counter []byte) {
	blockSize := block.BlockSize()
	gamma := make([]byte, blockSize)
	for len(src) > 0 {
		block.Encrypt(gamma, counter)
		n := min(blockSize, len(src))
		xorBytes(dst[:n], src[:n], gamma[:n])
		incHalf(counter[blockSize/2:])
		dst = dst[n:]
		src = src[n:]
	}
}

func xorBytes(dst, a, b []byte) {
	for i := range dst {
		dst[i] = a[i] ^ b[i]
	}
}

func shift(register, feedback []byte) {
	copy(register, register[len(feedback):])
	copy(register[len(register)-len(feedback):], feedback)
}

func incHalf(counter []byte) {
	for i := len(counter) - 1; i >= 0; i-- {
		counter[i]++
		if counter[i] != 0 {
			return
		}
	}
}
