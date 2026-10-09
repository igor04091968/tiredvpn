package gogost_test

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"errors"
	"testing"

	"gitverse.ru/uzer_007/gogost/v3/gost28147"
	"gitverse.ru/uzer_007/gogost/v3/gost3412128"
	"gitverse.ru/uzer_007/gogost/v3/gost341264"
	"gitverse.ru/uzer_007/gogost/v3/gost3413"
	"gitverse.ru/uzer_007/gogost/v3/mgm"
)

const gostModeCTRACPKMSectionSize = 1024

var gostModeACPKMD = [32]byte{
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
	0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
	0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
}

var (
	gostModeBytesSink []byte
	gostModeBoolSink  bool
	gostModeErrSink   error
)

type gostModeBenchSize struct {
	name string
	n    int
}

type gostCipherModeBench struct {
	name    string
	encrypt func([]byte) []byte
	decrypt func([]byte) ([]byte, error)
}

type gostMACModeBench struct {
	name  string
	tag   func([]byte) []byte
	check func([]byte, []byte) bool
}

var gostModeBenchSizes = []gostModeBenchSize{
	{"64B", 64},
	{"1KiB", 1024},
	{"16KiB", 16 * 1024},
	{"1MiB", 1024 * 1024},
}

func BenchmarkGOSTModes(b *testing.B) {
	key := gostModeKey()
	iv8 := gostModeIV(gost341264.BlockSize)
	iv16 := gostModeIV(gost3412128.BlockSize)

	kuznechik := gost3412128.NewCipher(key)
	magma := gost341264.NewCipher(key)
	legacy := gost28147.NewCipher(key, &gost28147.SboxIdGost2814789CryptoProAParamSet)

	kuznechikMGM, err := mgm.NewMGM(kuznechik, gost3412128.BlockSize)
	if err != nil {
		b.Fatal(err)
	}
	magmaMGM, err := mgm.NewMGM(magma, gost341264.BlockSize)
	if err != nil {
		b.Fatal(err)
	}

	benchmarkCipherModes(b, "Kuznechik", []gostCipherModeBench{
		{
			name:    "ECB-Pad2",
			encrypt: func(src []byte) []byte { return gostModeEncryptPaddedECB(kuznechik, src) },
			decrypt: func(src []byte) ([]byte, error) { return gostModeDecryptPaddedECB(kuznechik, src) },
		},
		{
			name:    "CBC-Pad2",
			encrypt: func(src []byte) []byte { return gostModeEncryptPaddedCBC(kuznechik, src, iv16) },
			decrypt: func(src []byte) ([]byte, error) { return gostModeDecryptPaddedCBC(kuznechik, src, iv16) },
		},
		{
			name:    "CTR",
			encrypt: func(src []byte) []byte { return gostModeCryptCTR(kuznechik, src, iv16) },
			decrypt: func(src []byte) ([]byte, error) { return gostModeCryptCTR(kuznechik, src, iv16), nil },
		},
		{
			name: "CTR-ACPKM",
			encrypt: func(src []byte) []byte {
				return gostModeCryptCTRACPKM(func(key []byte) cipher.Block {
					return gost3412128.NewCipher(key)
				}, kuznechik, src, key, iv16)
			},
			decrypt: func(src []byte) ([]byte, error) {
				return gostModeCryptCTRACPKM(func(key []byte) cipher.Block {
					return gost3412128.NewCipher(key)
				}, kuznechik, src, key, iv16), nil
			},
		},
		{
			name:    "CFB",
			encrypt: func(src []byte) []byte { return gostModeEncryptCFB(kuznechik, src, iv16) },
			decrypt: func(src []byte) ([]byte, error) { return gostModeDecryptCFB(kuznechik, src, iv16), nil },
		},
		{
			name:    "OFB",
			encrypt: func(src []byte) []byte { return gostModeEncryptOFB(kuznechik, src, iv16) },
			decrypt: func(src []byte) ([]byte, error) { return gostModeEncryptOFB(kuznechik, src, iv16), nil },
		},
		{
			name:    "MGM",
			encrypt: func(src []byte) []byte { return kuznechikMGM.Seal(nil, iv16, src, nil) },
			decrypt: func(src []byte) ([]byte, error) { return kuznechikMGM.Open(nil, iv16, src, nil) },
		},
	})
	benchmarkMACModes(b, "Kuznechik", []gostMACModeBench{
		{
			name: "MAC",
			tag: func(src []byte) []byte {
				tag, err := gostModeMAC(kuznechik, src, gost3412128.BlockSize)
				if err != nil {
					panic(err)
				}
				return tag
			},
			check: func(src, tag []byte) bool {
				expected, err := gostModeMAC(kuznechik, src, gost3412128.BlockSize)
				return err == nil && hmac.Equal(expected, tag)
			},
		},
	})

	benchmarkCipherModes(b, "Magma", []gostCipherModeBench{
		{
			name:    "ECB-Pad2",
			encrypt: func(src []byte) []byte { return gostModeEncryptPaddedECB(magma, src) },
			decrypt: func(src []byte) ([]byte, error) { return gostModeDecryptPaddedECB(magma, src) },
		},
		{
			name:    "CBC-Pad2",
			encrypt: func(src []byte) []byte { return gostModeEncryptPaddedCBC(magma, src, iv8) },
			decrypt: func(src []byte) ([]byte, error) { return gostModeDecryptPaddedCBC(magma, src, iv8) },
		},
		{
			name:    "CTR",
			encrypt: func(src []byte) []byte { return gostModeCryptCTR(magma, src, iv8) },
			decrypt: func(src []byte) ([]byte, error) { return gostModeCryptCTR(magma, src, iv8), nil },
		},
		{
			name: "CTR-ACPKM",
			encrypt: func(src []byte) []byte {
				return gostModeCryptCTRACPKM(func(key []byte) cipher.Block {
					return gost341264.NewCipher(key)
				}, magma, src, key, iv8)
			},
			decrypt: func(src []byte) ([]byte, error) {
				return gostModeCryptCTRACPKM(func(key []byte) cipher.Block {
					return gost341264.NewCipher(key)
				}, magma, src, key, iv8), nil
			},
		},
		{
			name:    "CFB",
			encrypt: func(src []byte) []byte { return gostModeEncryptCFB(magma, src, iv8) },
			decrypt: func(src []byte) ([]byte, error) { return gostModeDecryptCFB(magma, src, iv8), nil },
		},
		{
			name:    "OFB",
			encrypt: func(src []byte) []byte { return gostModeEncryptOFB(magma, src, iv8) },
			decrypt: func(src []byte) ([]byte, error) { return gostModeEncryptOFB(magma, src, iv8), nil },
		},
		{
			name:    "MGM",
			encrypt: func(src []byte) []byte { return magmaMGM.Seal(nil, iv8, src, nil) },
			decrypt: func(src []byte) ([]byte, error) { return magmaMGM.Open(nil, iv8, src, nil) },
		},
	})
	benchmarkMACModes(b, "Magma", []gostMACModeBench{
		{
			name: "MAC",
			tag: func(src []byte) []byte {
				tag, err := gostModeMAC(magma, src, gost341264.BlockSize)
				if err != nil {
					panic(err)
				}
				return tag
			},
			check: func(src, tag []byte) bool {
				expected, err := gostModeMAC(magma, src, gost341264.BlockSize)
				return err == nil && hmac.Equal(expected, tag)
			},
		},
	})

	benchmarkCipherModes(b, "GOST28147-89", []gostCipherModeBench{
		{
			name:    "ECB-Pad2",
			encrypt: func(src []byte) []byte { return gostModeEncryptPaddedECB(legacy, src) },
			decrypt: func(src []byte) ([]byte, error) { return gostModeDecryptPaddedECB(legacy, src) },
		},
		{
			name:    "CBC-Pad2",
			encrypt: func(src []byte) []byte { return gostModeEncryptPaddedCBC(legacy, src, iv8) },
			decrypt: func(src []byte) ([]byte, error) { return gostModeDecryptPaddedCBC(legacy, src, iv8) },
		},
		{
			name:    "CTR",
			encrypt: func(src []byte) []byte { return gostModeLegacyCTR(legacy, src, iv8) },
			decrypt: func(src []byte) ([]byte, error) { return gostModeLegacyCTR(legacy, src, iv8), nil },
		},
		{
			name:    "CFB",
			encrypt: func(src []byte) []byte { return gostModeLegacyCFBEncrypt(legacy, src, iv8) },
			decrypt: func(src []byte) ([]byte, error) { return gostModeLegacyCFBDecrypt(legacy, src, iv8), nil },
		},
	})
	benchmarkMACModes(b, "GOST28147-89", []gostMACModeBench{
		{
			name:  "MAC",
			tag:   func(src []byte) []byte { return gostModeLegacyMAC(legacy, src, iv8) },
			check: func(src, tag []byte) bool { return hmac.Equal(gostModeLegacyMAC(legacy, src, iv8), tag) },
		},
	})
}

func benchmarkCipherModes(b *testing.B, algorithm string, modes []gostCipherModeBench) {
	for _, mode := range modes {
		for _, size := range gostModeBenchSizes {
			plaintext := gostModePlaintext(size.n)
			ciphertext := mode.encrypt(plaintext)
			if len(ciphertext) == 0 {
				b.Fatalf("%s/%s/%s: empty ciphertext", algorithm, mode.name, size.name)
			}
			decrypted, err := mode.decrypt(ciphertext)
			if err != nil {
				b.Fatalf("%s/%s/%s: decrypt failed: %v", algorithm, mode.name, size.name, err)
			}
			if !bytes.Equal(decrypted, plaintext) {
				b.Fatalf("%s/%s/%s: round-trip mismatch", algorithm, mode.name, size.name)
			}

			b.Run(algorithm+"/"+mode.name+"/"+size.name+"/Encrypt", func(b *testing.B) {
				b.SetBytes(int64(size.n))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					gostModeBytesSink = mode.encrypt(plaintext)
				}
			})
			b.Run(algorithm+"/"+mode.name+"/"+size.name+"/Decrypt", func(b *testing.B) {
				b.SetBytes(int64(size.n))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					gostModeBytesSink, gostModeErrSink = mode.decrypt(ciphertext)
					if gostModeErrSink != nil {
						b.Fatal(gostModeErrSink)
					}
				}
			})
		}
	}
}

func benchmarkMACModes(b *testing.B, algorithm string, modes []gostMACModeBench) {
	for _, mode := range modes {
		for _, size := range gostModeBenchSizes {
			plaintext := gostModePlaintext(size.n)
			tag := mode.tag(plaintext)
			if len(tag) == 0 {
				b.Fatalf("%s/%s/%s: empty tag", algorithm, mode.name, size.name)
			}
			if !mode.check(plaintext, tag) {
				b.Fatalf("%s/%s/%s: MAC check failed", algorithm, mode.name, size.name)
			}

			b.Run(algorithm+"/"+mode.name+"/"+size.name+"/Tag", func(b *testing.B) {
				b.SetBytes(int64(size.n))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					gostModeBytesSink = mode.tag(plaintext)
				}
			})
			b.Run(algorithm+"/"+mode.name+"/"+size.name+"/Check", func(b *testing.B) {
				b.SetBytes(int64(size.n))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					gostModeBoolSink = mode.check(plaintext, tag)
					if !gostModeBoolSink {
						b.Fatal("MAC check failed")
					}
				}
			})
		}
	}
}

func gostModeKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func gostModeIV(size int) []byte {
	iv := make([]byte, size)
	for i := range iv {
		iv[i] = byte(i + 1)
	}
	return iv
}

func gostModePlaintext(size int) []byte {
	plaintext := make([]byte, size)
	for i := range plaintext {
		plaintext[i] = byte(17 + i*31)
	}
	return plaintext
}

func gostModeEncryptPaddedCBC(block cipher.Block, plaintext, iv []byte) []byte {
	padded := gost3413.Pad2(bytes.Clone(plaintext), block.BlockSize())
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	return ciphertext
}

func gostModeDecryptPaddedCBC(block cipher.Block, ciphertext, iv []byte) ([]byte, error) {
	blockSize := block.BlockSize()
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
	return gost3413.Unpad2(plaintext, blockSize)
}

func gostModeEncryptPaddedECB(block cipher.Block, plaintext []byte) []byte {
	blockSize := block.BlockSize()
	padded := gost3413.Pad2(bytes.Clone(plaintext), blockSize)
	ciphertext := make([]byte, len(padded))
	for offset := 0; offset < len(padded); offset += blockSize {
		block.Encrypt(ciphertext[offset:offset+blockSize], padded[offset:offset+blockSize])
	}
	return ciphertext
}

func gostModeDecryptPaddedECB(block cipher.Block, ciphertext []byte) ([]byte, error) {
	blockSize := block.BlockSize()
	plaintext := make([]byte, len(ciphertext))
	for offset := 0; offset < len(ciphertext); offset += blockSize {
		block.Decrypt(plaintext[offset:offset+blockSize], ciphertext[offset:offset+blockSize])
	}
	return gost3413.Unpad2(plaintext, blockSize)
}

func gostModeEncryptCFB(block cipher.Block, plaintext, iv []byte) []byte {
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCFBEncrypter(block, iv).XORKeyStream(ciphertext, plaintext)
	return ciphertext
}

func gostModeDecryptCFB(block cipher.Block, ciphertext, iv []byte) []byte {
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCFBDecrypter(block, iv).XORKeyStream(plaintext, ciphertext)
	return plaintext
}

func gostModeEncryptOFB(block cipher.Block, plaintext, iv []byte) []byte {
	ciphertext := make([]byte, len(plaintext))
	cipher.NewOFB(block, iv).XORKeyStream(ciphertext, plaintext)
	return ciphertext
}

func gostModeNormalizeCTRIV(iv []byte, blockSize int) []byte {
	counter := make([]byte, blockSize)
	switch len(iv) {
	case blockSize:
		copy(counter, iv)
	case blockSize / 2:
		copy(counter, iv)
	default:
		panic("gogost/benchmark: Некорректный размер IV для CTR")
	}
	return counter
}

func gostModeIncCounter(counter []byte) {
	for i := len(counter) - 1; i >= 0; i-- {
		counter[i]++
		if counter[i] != 0 {
			return
		}
	}
}

func gostModeXORCTR(dst, src []byte, block cipher.Block, counter []byte) {
	blockSize := block.BlockSize()
	gamma := make([]byte, blockSize)
	for len(src) > 0 {
		block.Encrypt(gamma, counter)
		n := min(len(src), blockSize)
		for i := 0; i < n; i++ {
			dst[i] = src[i] ^ gamma[i]
		}
		gostModeIncCounter(counter[blockSize/2:])
		dst = dst[n:]
		src = src[n:]
	}
}

func gostModeCryptCTR(block cipher.Block, input, iv []byte) []byte {
	output := make([]byte, len(input))
	counter := gostModeNormalizeCTRIV(iv, block.BlockSize())
	gostModeXORCTR(output, input, block, counter)
	return output
}

func gostModeDeriveACPKMKey(block cipher.Block, keySize int) []byte {
	blockSize := block.BlockSize()
	nextKey := make([]byte, 0, keySize)
	buf := make([]byte, blockSize)
	for offset := 0; len(nextKey) < keySize; offset += blockSize {
		block.Encrypt(buf, gostModeACPKMD[offset:offset+blockSize])
		need := min(blockSize, keySize-len(nextKey))
		nextKey = append(nextKey, buf[:need]...)
	}
	return nextKey
}

func gostModeCryptCTRACPKM(newBlock func([]byte) cipher.Block, firstBlock cipher.Block, input, key, iv []byte) []byte {
	currentKey := bytes.Clone(key)
	block := firstBlock
	counter := gostModeNormalizeCTRIV(iv, block.BlockSize())
	output := make([]byte, len(input))

	for offset := 0; offset < len(input); {
		sectionSize := min(gostModeCTRACPKMSectionSize, len(input)-offset)
		gostModeXORCTR(output[offset:offset+sectionSize], input[offset:offset+sectionSize], block, counter)
		offset += sectionSize
		if offset < len(input) {
			currentKey = gostModeDeriveACPKMKey(block, len(currentKey))
			block = newBlock(currentKey)
		}
	}

	return output
}

func gostModeDoubleSubkey(k []byte) []byte {
	out := make([]byte, len(k))
	var carry byte
	for i := len(k) - 1; i >= 0; i-- {
		nextCarry := k[i] >> 7
		out[i] = (k[i] << 1) | carry
		carry = nextCarry
	}
	if carry != 0 {
		switch len(k) {
		case 8:
			out[len(out)-1] ^= 0x1b
		case 16:
			out[len(out)-1] ^= 0x87
		default:
			panic("gogost/benchmark: Некорректный размер блока MAC")
		}
	}
	return out
}

func gostModeXORBlock(dst, a, b []byte) {
	for i := range dst {
		dst[i] = a[i] ^ b[i]
	}
}

func gostModeMAC(block cipher.Block, data []byte, tagSize int) ([]byte, error) {
	blockSize := block.BlockSize()
	if tagSize <= 0 || tagSize > blockSize {
		return nil, errors.New("gogost/benchmark: Некорректный размер тега MAC")
	}

	zero := make([]byte, blockSize)
	l := make([]byte, blockSize)
	block.Encrypt(l, zero)
	k1 := gostModeDoubleSubkey(l)
	k2 := gostModeDoubleSubkey(k1)

	var fullBlocks int
	last := make([]byte, blockSize)
	if len(data) > 0 && len(data)%blockSize == 0 {
		fullBlocks = len(data)/blockSize - 1
		gostModeXORBlock(last, data[len(data)-blockSize:], k1)
	} else {
		fullBlocks = len(data) / blockSize
		padded := gost3413.Pad2(bytes.Clone(data[fullBlocks*blockSize:]), blockSize)
		gostModeXORBlock(last, padded, k2)
	}

	state := make([]byte, blockSize)
	for i := 0; i < fullBlocks; i++ {
		gostModeXORBlock(state, state, data[i*blockSize:(i+1)*blockSize])
		block.Encrypt(state, state)
	}
	gostModeXORBlock(state, state, last)
	block.Encrypt(state, state)

	tag := make([]byte, tagSize)
	copy(tag, state[:tagSize])
	return tag, nil
}

func gostModeLegacyCTR(block *gost28147.Cipher, input, iv []byte) []byte {
	output := make([]byte, len(input))
	block.NewCTR(iv).XORKeyStream(output, input)
	return output
}

func gostModeLegacyCFBEncrypt(block *gost28147.Cipher, plaintext, iv []byte) []byte {
	ciphertext := make([]byte, len(plaintext))
	block.NewCFBEncrypter(iv).XORKeyStream(ciphertext, plaintext)
	return ciphertext
}

func gostModeLegacyCFBDecrypt(block *gost28147.Cipher, ciphertext, iv []byte) []byte {
	plaintext := make([]byte, len(ciphertext))
	block.NewCFBDecrypter(iv).XORKeyStream(plaintext, ciphertext)
	return plaintext
}

func gostModeLegacyMAC(block *gost28147.Cipher, plaintext, iv []byte) []byte {
	mac, err := block.NewMAC(gost28147.BlockSize, iv)
	if err != nil {
		panic(err)
	}
	_, _ = mac.Write(plaintext)
	return mac.Sum(nil)
}
