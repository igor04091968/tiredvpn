package gost3412128

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"testing"

	"gitverse.ru/uzer_007/gogost/v3/gost3413"
	"gitverse.ru/uzer_007/gogost/v3/mgm"
)

const kuznechikCTRACPKMSectionSize = 1024

var kuznechikACPKMD = [32]byte{
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
	0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
	0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
}

var (
	kuznechikModeBytesSink []byte
	kuznechikModeBoolSink  bool
	kuznechikModeErrSink   error
)

type kuznechikModeBenchSize struct {
	name string
	n    int
}

type kuznechikCipherModeBench struct {
	name    string
	encrypt func([]byte) []byte
	decrypt func([]byte) ([]byte, error)
}

type kuznechikMACModeBench struct {
	name  string
	tag   func([]byte) []byte
	check func([]byte, []byte) bool
}

var kuznechikModeBenchSizes = []kuznechikModeBenchSize{
	{"16B", 16},
	{"64B", 64},
	{"1KiB", 1024},
	{"16KiB", 16 * 1024},
	{"1MiB", 1024 * 1024},
}

func BenchmarkKuznechikModes(b *testing.B) {
	key := append([]byte(nil), Key...)
	iv := kuznechikModeIV(BlockSize)
	block := NewCipher(key)
	aead, err := mgm.NewMGM(block, BlockSize)
	if err != nil {
		b.Fatal(err)
	}

	benchmarkKuznechikCipherModes(b, []kuznechikCipherModeBench{
		{
			name:    "ECB-Pad2",
			encrypt: func(src []byte) []byte { return kuznechikModeEncryptPaddedECB(block, src) },
			decrypt: func(src []byte) ([]byte, error) { return kuznechikModeDecryptPaddedECB(block, src) },
		},
		{
			name:    "CBC-Pad2",
			encrypt: func(src []byte) []byte { return kuznechikModeEncryptPaddedCBC(block, src, iv) },
			decrypt: func(src []byte) ([]byte, error) { return kuznechikModeDecryptPaddedCBC(block, src, iv) },
		},
		{
			name:    "CTR",
			encrypt: func(src []byte) []byte { return kuznechikModeCryptCTR(block, src, iv) },
			decrypt: func(src []byte) ([]byte, error) { return kuznechikModeCryptCTR(block, src, iv), nil },
		},
		{
			name: "CTR-ACPKM",
			encrypt: func(src []byte) []byte {
				return kuznechikModeCryptCTRACPKM(src, key, iv)
			},
			decrypt: func(src []byte) ([]byte, error) {
				return kuznechikModeCryptCTRACPKM(src, key, iv), nil
			},
		},
		{
			name:    "CFB",
			encrypt: func(src []byte) []byte { return kuznechikModeEncryptCFB(block, src, iv) },
			decrypt: func(src []byte) ([]byte, error) { return kuznechikModeDecryptCFB(block, src, iv), nil },
		},
		{
			name:    "OFB",
			encrypt: func(src []byte) []byte { return kuznechikModeEncryptOFB(block, src, iv) },
			decrypt: func(src []byte) ([]byte, error) { return kuznechikModeEncryptOFB(block, src, iv), nil },
		},
		{
			name:    "MGM",
			encrypt: func(src []byte) []byte { return aead.Seal(nil, iv, src, nil) },
			decrypt: func(src []byte) ([]byte, error) { return aead.Open(nil, iv, src, nil) },
		},
	})
	benchmarkKuznechikMACModes(b, []kuznechikMACModeBench{
		{
			name: "MAC",
			tag:  func(src []byte) []byte { return kuznechikModeMAC(block, src) },
			check: func(src, tag []byte) bool {
				return hmac.Equal(kuznechikModeMAC(block, src), tag)
			},
		},
	})
}

func benchmarkKuznechikCipherModes(b *testing.B, modes []kuznechikCipherModeBench) {
	for _, mode := range modes {
		for _, size := range kuznechikModeBenchSizes {
			plaintext := kuznechikModePlaintext(size.n)
			ciphertext := mode.encrypt(plaintext)
			decrypted, err := mode.decrypt(ciphertext)
			if err != nil {
				b.Fatalf("%s/%s: decrypt failed: %v", mode.name, size.name, err)
			}
			if !bytes.Equal(decrypted, plaintext) {
				b.Fatalf("%s/%s: round-trip mismatch", mode.name, size.name)
			}

			b.Run(mode.name+"/"+size.name+"/Encrypt", func(b *testing.B) {
				b.SetBytes(int64(size.n))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					kuznechikModeBytesSink = mode.encrypt(plaintext)
				}
			})
			b.Run(mode.name+"/"+size.name+"/Decrypt", func(b *testing.B) {
				b.SetBytes(int64(size.n))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					kuznechikModeBytesSink, kuznechikModeErrSink = mode.decrypt(ciphertext)
					if kuznechikModeErrSink != nil {
						b.Fatal(kuznechikModeErrSink)
					}
				}
			})
		}
	}
}

func benchmarkKuznechikMACModes(b *testing.B, modes []kuznechikMACModeBench) {
	for _, mode := range modes {
		for _, size := range kuznechikModeBenchSizes {
			plaintext := kuznechikModePlaintext(size.n)
			tag := mode.tag(plaintext)
			if !mode.check(plaintext, tag) {
				b.Fatalf("%s/%s: MAC check failed", mode.name, size.name)
			}

			b.Run(mode.name+"/"+size.name+"/Tag", func(b *testing.B) {
				b.SetBytes(int64(size.n))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					kuznechikModeBytesSink = mode.tag(plaintext)
				}
			})
			b.Run(mode.name+"/"+size.name+"/Check", func(b *testing.B) {
				b.SetBytes(int64(size.n))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					kuznechikModeBoolSink = mode.check(plaintext, tag)
					if !kuznechikModeBoolSink {
						b.Fatal("MAC check failed")
					}
				}
			})
		}
	}
}

func kuznechikModeIV(size int) []byte {
	iv := make([]byte, size)
	for i := range iv {
		iv[i] = byte(i + 1)
	}
	return iv
}

func kuznechikModePlaintext(size int) []byte {
	plaintext := make([]byte, size)
	for i := range plaintext {
		plaintext[i] = byte(17 + i*31)
	}
	return plaintext
}

func kuznechikModeEncryptPaddedCBC(block cipher.Block, plaintext, iv []byte) []byte {
	padded := gost3413.Pad2(bytes.Clone(plaintext), block.BlockSize())
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	return ciphertext
}

func kuznechikModeDecryptPaddedCBC(block cipher.Block, ciphertext, iv []byte) ([]byte, error) {
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
	return gost3413.Unpad2(plaintext, block.BlockSize())
}

func kuznechikModeEncryptPaddedECB(block cipher.Block, plaintext []byte) []byte {
	blockSize := block.BlockSize()
	padded := gost3413.Pad2(bytes.Clone(plaintext), blockSize)
	ciphertext := make([]byte, len(padded))
	for offset := 0; offset < len(padded); offset += blockSize {
		block.Encrypt(ciphertext[offset:offset+blockSize], padded[offset:offset+blockSize])
	}
	return ciphertext
}

func kuznechikModeDecryptPaddedECB(block cipher.Block, ciphertext []byte) ([]byte, error) {
	blockSize := block.BlockSize()
	plaintext := make([]byte, len(ciphertext))
	for offset := 0; offset < len(ciphertext); offset += blockSize {
		block.Decrypt(plaintext[offset:offset+blockSize], ciphertext[offset:offset+blockSize])
	}
	return gost3413.Unpad2(plaintext, blockSize)
}

func kuznechikModeEncryptCFB(block cipher.Block, plaintext, iv []byte) []byte {
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCFBEncrypter(block, iv).XORKeyStream(ciphertext, plaintext)
	return ciphertext
}

func kuznechikModeDecryptCFB(block cipher.Block, ciphertext, iv []byte) []byte {
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCFBDecrypter(block, iv).XORKeyStream(plaintext, ciphertext)
	return plaintext
}

func kuznechikModeEncryptOFB(block cipher.Block, plaintext, iv []byte) []byte {
	ciphertext := make([]byte, len(plaintext))
	cipher.NewOFB(block, iv).XORKeyStream(ciphertext, plaintext)
	return ciphertext
}

func kuznechikModeNormalizeCTRIV(iv []byte) []byte {
	counter := make([]byte, BlockSize)
	switch len(iv) {
	case BlockSize:
		copy(counter, iv)
	case BlockSize / 2:
		copy(counter, iv)
	default:
		panic("gogost/gost3412128: Некорректный размер IV для CTR")
	}
	return counter
}

func kuznechikModeIncCounter(counter []byte) {
	for i := len(counter) - 1; i >= 0; i-- {
		counter[i]++
		if counter[i] != 0 {
			return
		}
	}
}

func kuznechikModeXORCTR(dst, src []byte, block cipher.Block, counter []byte) {
	var gamma [BlockSize]byte
	for len(src) > 0 {
		block.Encrypt(gamma[:], counter)
		n := min(len(src), BlockSize)
		for i := 0; i < n; i++ {
			dst[i] = src[i] ^ gamma[i]
		}
		kuznechikModeIncCounter(counter[BlockSize/2:])
		dst = dst[n:]
		src = src[n:]
	}
}

func kuznechikModeCryptCTR(block cipher.Block, input, iv []byte) []byte {
	output := make([]byte, len(input))
	counter := kuznechikModeNormalizeCTRIV(iv)
	kuznechikModeXORCTR(output, input, block, counter)
	return output
}

func kuznechikModeDeriveACPKMKey(block cipher.Block, keySize int) []byte {
	nextKey := make([]byte, 0, keySize)
	var buf [BlockSize]byte
	for offset := 0; len(nextKey) < keySize; offset += BlockSize {
		block.Encrypt(buf[:], kuznechikACPKMD[offset:offset+BlockSize])
		need := min(BlockSize, keySize-len(nextKey))
		nextKey = append(nextKey, buf[:need]...)
	}
	return nextKey
}

func kuznechikModeCryptCTRACPKM(input, key, iv []byte) []byte {
	currentKey := bytes.Clone(key)
	block := NewCipher(currentKey)
	counter := kuznechikModeNormalizeCTRIV(iv)
	output := make([]byte, len(input))

	for offset := 0; offset < len(input); {
		sectionSize := min(kuznechikCTRACPKMSectionSize, len(input)-offset)
		kuznechikModeXORCTR(output[offset:offset+sectionSize], input[offset:offset+sectionSize], block, counter)
		offset += sectionSize
		if offset < len(input) {
			currentKey = kuznechikModeDeriveACPKMKey(block, len(currentKey))
			block = NewCipher(currentKey)
		}
	}

	return output
}

func kuznechikModeDoubleSubkey(k []byte) []byte {
	out := make([]byte, len(k))
	var carry byte
	for i := len(k) - 1; i >= 0; i-- {
		nextCarry := k[i] >> 7
		out[i] = (k[i] << 1) | carry
		carry = nextCarry
	}
	if carry != 0 {
		out[len(out)-1] ^= 0x87
	}
	return out
}

func kuznechikModeXORBlock(dst, a, b []byte) {
	for i := range dst {
		dst[i] = a[i] ^ b[i]
	}
}

func kuznechikModeMAC(block cipher.Block, data []byte) []byte {
	var zero [BlockSize]byte
	var l [BlockSize]byte
	block.Encrypt(l[:], zero[:])
	k1 := kuznechikModeDoubleSubkey(l[:])
	k2 := kuznechikModeDoubleSubkey(k1)

	var fullBlocks int
	last := make([]byte, BlockSize)
	if len(data) > 0 && len(data)%BlockSize == 0 {
		fullBlocks = len(data)/BlockSize - 1
		kuznechikModeXORBlock(last, data[len(data)-BlockSize:], k1)
	} else {
		fullBlocks = len(data) / BlockSize
		padded := gost3413.Pad2(bytes.Clone(data[fullBlocks*BlockSize:]), BlockSize)
		kuznechikModeXORBlock(last, padded, k2)
	}

	state := make([]byte, BlockSize)
	for i := 0; i < fullBlocks; i++ {
		kuznechikModeXORBlock(state, state, data[i*BlockSize:(i+1)*BlockSize])
		block.Encrypt(state, state)
	}
	kuznechikModeXORBlock(state, state, last)
	block.Encrypt(state, state)
	return bytes.Clone(state)
}
