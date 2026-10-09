package modes_test

import (
	"crypto/cipher"
	"strconv"
	"testing"

	"gitverse.ru/uzer_007/gogost/v3/gost28147"
	"gitverse.ru/uzer_007/gogost/v3/gost3412128"
	"gitverse.ru/uzer_007/gogost/v3/gost341264"
	"gitverse.ru/uzer_007/gogost/v3/gost3413/modes"
)

var (
	benchBytes []byte
	benchBool  bool
	benchErr   error
)

type benchMode interface {
	Encrypt([]byte, []byte) ([]byte, error)
	Decrypt([]byte, []byte) ([]byte, error)
}

type benchStream interface {
	XORKeyStream([]byte, []byte) ([]byte, error)
}

type benchEngine struct {
	name      string
	blockSize int
	newEngine func() testEngine
}

type lowLevelBenchBlock interface {
	cipher.Block
	EncryptBlocks(dst, src []byte)
	DecryptBlocks(dst, src []byte)
	EncryptCBC(dst, src, iv []byte)
	DecryptCBC(dst, src, iv []byte)
	EncryptCFB(dst, src, iv []byte)
	DecryptCFB(dst, src, iv []byte)
	XORKeyStreamOFB(dst, src, iv []byte)
	XORKeyStreamCTRCounter(dst, src, counter []byte)
	SumGOST3413MAC(dst, data []byte, tagSize int) []byte
}

func BenchmarkPreparedCreation(b *testing.B) {
	key := testKey()
	for _, tc := range []struct {
		name string
		new  func() error
	}{
		{"Kuznechik", func() error {
			engine, err := modes.NewKuznechik(key)
			if err != nil {
				return err
			}
			_, err = engine.CTRACPKM(testIV(gost3412128.BlockSize), modes.DefaultACPKMSectionSize)
			return err
		}},
		{"Magma", func() error {
			engine, err := modes.NewMagma(key)
			if err != nil {
				return err
			}
			_, err = engine.CTRACPKM(testIV(gost341264.BlockSize), modes.DefaultACPKMSectionSize)
			return err
		}},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := tc.new(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkPreparedModeCreation(b *testing.B) {
	for _, engine := range benchEngines() {
		e := engine.newEngine()
		iv := testIV(engine.blockSize)
		b.Run(engine.name+"/ECB", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = e.ECB(modes.PaddingNone)
			}
		})
		b.Run(engine.name+"/CBC", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := e.CBC(iv, modes.PaddingNone); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(engine.name+"/CFB", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := e.CFB(iv); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(engine.name+"/OFB", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := e.OFB(iv); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(engine.name+"/CTR", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := e.CTR(iv); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(engine.name+"/CTR-ACPKM", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := e.CTRACPKM(iv, modes.DefaultACPKMSectionSize); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(engine.name+"/MAC", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := e.MAC(engine.blockSize); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkPreparedModes(b *testing.B) {
	for _, engine := range benchEngines() {
		for _, size := range benchSizes() {
			plaintext := testPlaintext(size.n)
			iv := testIV(engine.blockSize)
			e := engine.newEngine()

			benchPreparedBlockMode(b, engine.name, "ECB", size.name, size.n, e.ECB(modes.PaddingDefault), plaintext)
			benchPreparedBlockMode(b, engine.name, "CBC", size.name, size.n, mustMode(e.CBC(iv, modes.PaddingDefault)), plaintext)
			benchPreparedBlockMode(b, engine.name, "CFB", size.name, size.n, mustMode(e.CFB(iv)), plaintext)
			ofb := mustMode(e.OFB(iv))
			benchPreparedBlockMode(b, engine.name, "OFB", size.name, size.n, ofb, plaintext)
			benchPreparedStream(b, engine.name, "OFB/XOR", size.name, size.n, ofb, plaintext)
			ctr := mustMode(e.CTR(iv))
			benchPreparedBlockMode(b, engine.name, "CTR", size.name, size.n, ctr, plaintext)
			benchPreparedStream(b, engine.name, "CTR/XOR", size.name, size.n, ctr, plaintext)
			acpkm := mustMode(e.CTRACPKM(iv, modes.DefaultACPKMSectionSize))
			if _, err := acpkm.Encrypt(make([]byte, 0, size.n), plaintext); err != nil {
				b.Fatal(err)
			}
			benchPreparedBlockMode(b, engine.name, "CTR-ACPKM/warm", size.name, size.n, acpkm, plaintext)
			benchPreparedStream(b, engine.name, "CTR-ACPKM/XOR/warm", size.name, size.n, acpkm, plaintext)
			benchPreparedMGM(b, engine.name, size.name, size.n, mustMode(e.MGM(0)), iv, plaintext, []byte("metadata"))
		}
	}
}

func BenchmarkSingleBlockPaddingNone(b *testing.B) {
	for _, engine := range benchEngines() {
		plaintext := testPlaintext(engine.blockSize)
		iv := testIV(engine.blockSize)
		e := engine.newEngine()

		benchPreparedBlockMode(b, engine.name, "ECB/PaddingNone", "1Block", engine.blockSize, e.ECB(modes.PaddingNone), plaintext)
		benchPreparedBlockMode(b, engine.name, "CBC/PaddingNone", "1Block", engine.blockSize, mustMode(e.CBC(iv, modes.PaddingNone)), plaintext)
		benchPreparedBlockMode(b, engine.name, "CFB", "1Block", engine.blockSize, mustMode(e.CFB(iv)), plaintext)
		ofb := mustMode(e.OFB(iv))
		benchPreparedStream(b, engine.name, "OFB/XOR", "1Block", engine.blockSize, ofb, plaintext)
		ctr := mustMode(e.CTR(iv))
		benchPreparedStream(b, engine.name, "CTR/XOR", "1Block", engine.blockSize, ctr, plaintext)
		mac := mustMode(e.MAC(engine.blockSize))
		b.Run(engine.name+"/MAC/Sum/1Block", func(b *testing.B) {
			dst := make([]byte, 0, engine.blockSize)
			b.SetBytes(int64(engine.blockSize))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchBytes = mac.Sum(dst[:0], plaintext)
			}
		})
	}
}

func BenchmarkSingleBlockTo(b *testing.B) {
	for _, engine := range benchEngines() {
		plaintext := testPlaintext(engine.blockSize)
		iv := testIV(engine.blockSize)
		e := engine.newEngine()

		benchBlockTo(b, engine.name, "ECB/PaddingNone", e.ECB(modes.PaddingNone), plaintext)
		benchBlockTo(b, engine.name, "CBC/PaddingNone", mustMode(e.CBC(iv, modes.PaddingNone)), plaintext)
		benchBlockTo(b, engine.name, "CFB", mustMode(e.CFB(iv)), plaintext)
		benchStreamTo(b, engine.name, "OFB", mustMode(e.OFB(iv)), plaintext)
		benchStreamTo(b, engine.name, "CTR", mustMode(e.CTR(iv)), plaintext)
	}
}

func BenchmarkCTRACPKMFirstCall(b *testing.B) {
	for _, engine := range benchEngines() {
		iv := testIV(engine.blockSize)
		for _, size := range benchSizes() {
			plaintext := testPlaintext(size.n)
			b.Run(engine.name+"/"+size.name, func(b *testing.B) {
				e := engine.newEngine()
				b.SetBytes(int64(size.n))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					acpkm := mustMode(e.CTRACPKM(iv, modes.DefaultACPKMSectionSize))
					benchBytes, benchErr = acpkm.Encrypt(make([]byte, 0, len(plaintext)), plaintext)
					if benchErr != nil {
						b.Fatal(benchErr)
					}
				}
			})
		}
	}
}

func BenchmarkCTRACPKMPrecompute(b *testing.B) {
	for _, engine := range benchEngines() {
		iv := testIV(engine.blockSize)
		for _, size := range benchSizes() {
			plaintext := testPlaintext(size.n)
			b.Run(engine.name+"/"+size.name, func(b *testing.B) {
				e := engine.newEngine()
				acpkm := mustMode(e.CTRACPKM(iv, modes.DefaultACPKMSectionSize))
				if err := acpkm.PrecomputeSections(len(plaintext)); err != nil {
					b.Fatal(err)
				}
				dst := make([]byte, 0, len(plaintext))
				b.SetBytes(int64(size.n))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					benchBytes, benchErr = acpkm.Encrypt(dst[:0], plaintext)
					if benchErr != nil {
						b.Fatal(benchErr)
					}
				}
			})
		}
	}
}

func BenchmarkHighLevelVsLowLevel(b *testing.B) {
	key := testKey()
	benchHighLevelVsLowLevel(b, "Magma", gost341264.BlockSize, gost341264.NewCipher(key), modes.MustMagma(key))
	benchHighLevelVsLowLevel(b, "GOST28147", gost28147.BlockSize, gost28147.NewCipher(key, gost28147.SboxDefault), modes.MustGOST28147Default(key))
	benchHighLevelVsLowLevel(b, "Kuznechik", gost3412128.BlockSize, gost3412128.NewCipher(key), modes.MustKuznechik(key))
}

func BenchmarkParallelModes(b *testing.B) {
	for _, engine := range benchEngines() {
		e := engine.newEngine()
		iv := testIV(engine.blockSize)
		for _, size := range parallelBenchSizes() {
			alignedLen := size.n - size.n%engine.blockSize
			if alignedLen == 0 {
				alignedLen = engine.blockSize
			}
			aligned := testPlaintext(alignedLen)
			stream := testPlaintext(size.n)

			ecb := e.ECB(modes.PaddingNone)
			benchParallelBlockEncrypt(b, engine.name, "ECB", size.name, alignedLen, ecb, aligned)

			cbc := mustMode(e.CBC(iv, modes.PaddingNone))
			cbcCiphertext, err := cbc.Encrypt(nil, aligned)
			if err != nil {
				b.Fatal(err)
			}
			benchParallelBlockDecrypt(b, engine.name, "CBC", size.name, alignedLen, cbc, cbcCiphertext)

			cfb := mustMode(e.CFB(iv))
			cfbCiphertext, err := cfb.Encrypt(nil, stream)
			if err != nil {
				b.Fatal(err)
			}
			benchParallelBlockDecrypt(b, engine.name, "CFB", size.name, size.n, cfb, cfbCiphertext)

			ctr := mustMode(e.CTR(iv))
			benchParallelStream(b, engine.name, "CTR", size.name, size.n, ctr, stream)

			acpkm := mustMode(e.CTRACPKM(iv, modes.DefaultACPKMSectionSize))
			if err := acpkm.PrecomputeSections(size.n); err != nil {
				b.Fatal(err)
			}
			benchParallelStream(b, engine.name, "CTR-ACPKM/warm", size.name, size.n, acpkm, stream)
		}
	}
}

func BenchmarkECBQuality(b *testing.B) {
	key := testKey()
	for _, tc := range []struct {
		name      string
		blockSize int
		block     lowLevelBenchBlock
		engine    testEngine
	}{
		{
			name:      "Magma",
			blockSize: gost341264.BlockSize,
			block:     gost341264.NewCipher(key),
			engine:    mustMode(modes.NewMagma(key)),
		},
		{
			name:      "Kuznechik",
			blockSize: gost3412128.BlockSize,
			block:     gost3412128.NewCipher(key),
			engine:    mustMode(modes.NewKuznechik(key)),
		},
	} {
		for _, size := range []struct {
			name string
			n    int
		}{
			{"1Block", tc.blockSize},
			{"2Blocks", 2 * tc.blockSize},
			{"4Blocks", 4 * tc.blockSize},
			{"8Blocks", 8 * tc.blockSize},
			{"64B", 64},
			{"128B", 128},
			{"1KiB", 1024},
			{"16KiB", 16 * 1024},
			{"1MiB", 1 << 20},
			{"16MiB", 16 << 20},
		} {
			n := size.n - size.n%tc.blockSize
			src := make([]byte, n)
			for i := range src {
				src[i] = byte(i*31 + 17)
			}
			dst := make([]byte, n)
			ecb := tc.engine.ECB(modes.PaddingNone)

			b.Run(tc.name+"/LowLevel/"+size.name, func(b *testing.B) {
				b.SetBytes(int64(n))
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					tc.block.EncryptBlocks(dst, src)
				}
				benchBytes = dst
			})
			b.Run(tc.name+"/Modes/"+size.name, func(b *testing.B) {
				out := make([]byte, 0, n)
				b.SetBytes(int64(n))
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					var err error
					benchBytes, err = ecb.Encrypt(out[:0], src)
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func BenchmarkMAC(b *testing.B) {
	for _, engine := range benchEngines() {
		e := engine.newEngine()
		mac := mustMode(e.MAC(engine.blockSize))
		for _, size := range benchSizes() {
			plaintext := testPlaintext(size.n)
			tag := mac.Sum(nil, plaintext)
			b.Run(engine.name+"/Sum/"+size.name, func(b *testing.B) {
				dst := make([]byte, 0, engine.blockSize)
				b.SetBytes(int64(size.n))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					benchBytes = mac.Sum(dst[:0], plaintext)
				}
			})
			b.Run(engine.name+"/Verify/"+size.name, func(b *testing.B) {
				b.SetBytes(int64(size.n))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					benchBool = mac.Verify(plaintext, tag)
					if !benchBool {
						b.Fatal("MAC verify failed")
					}
				}
			})
		}
	}
}

type parallelBlockEncryptMode interface {
	Encrypt([]byte, []byte) ([]byte, error)
	EncryptWithWorkers([]byte, []byte, int) ([]byte, error)
}

type parallelBlockDecryptMode interface {
	Decrypt([]byte, []byte) ([]byte, error)
	DecryptWithWorkers([]byte, []byte, int) ([]byte, error)
}

type parallelStreamMode interface {
	XORKeyStream([]byte, []byte) ([]byte, error)
	XORKeyStreamWithWorkers([]byte, []byte, int) ([]byte, error)
}

type benchWorkerConfigurable interface {
	SetWorkers(int) error
	Close()
}

func benchParallelBlockEncrypt(
	b *testing.B,
	engine, mode, sizeName string,
	n int,
	prepared parallelBlockEncryptMode,
	plaintext []byte,
) {
	b.Run(engine+"/"+mode+"/"+sizeName+"/AutoEncrypt", func(b *testing.B) {
		dst := make([]byte, 0, len(plaintext))
		b.SetBytes(int64(n))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchBytes, benchErr = prepared.Encrypt(dst[:0], plaintext)
			if benchErr != nil {
				b.Fatal(benchErr)
			}
		}
	})
	for _, workers := range []int{2, 4, 8} {
		b.Run(engine+"/"+mode+"/"+sizeName+"/Manual"+itoaBench(workers)+"Encrypt", func(b *testing.B) {
			dst := make([]byte, 0, len(plaintext))
			if configurable, ok := prepared.(benchWorkerConfigurable); ok {
				if err := configurable.SetWorkers(workers); err != nil {
					b.Fatal(err)
				}
				b.Cleanup(configurable.Close)
			}
			b.SetBytes(int64(n))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchBytes, benchErr = prepared.EncryptWithWorkers(dst[:0], plaintext, workers)
				if benchErr != nil {
					b.Fatal(benchErr)
				}
			}
		})
	}
}

func benchParallelBlockDecrypt(
	b *testing.B,
	engine, mode, sizeName string,
	n int,
	prepared parallelBlockDecryptMode,
	ciphertext []byte,
) {
	b.Run(engine+"/"+mode+"/"+sizeName+"/AutoDecrypt", func(b *testing.B) {
		dst := make([]byte, 0, len(ciphertext))
		b.SetBytes(int64(n))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchBytes, benchErr = prepared.Decrypt(dst[:0], ciphertext)
			if benchErr != nil {
				b.Fatal(benchErr)
			}
		}
	})
	for _, workers := range []int{2, 4, 8} {
		b.Run(engine+"/"+mode+"/"+sizeName+"/Manual"+itoaBench(workers)+"Decrypt", func(b *testing.B) {
			dst := make([]byte, 0, len(ciphertext))
			if configurable, ok := prepared.(benchWorkerConfigurable); ok {
				if err := configurable.SetWorkers(workers); err != nil {
					b.Fatal(err)
				}
				b.Cleanup(configurable.Close)
			}
			b.SetBytes(int64(n))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchBytes, benchErr = prepared.DecryptWithWorkers(dst[:0], ciphertext, workers)
				if benchErr != nil {
					b.Fatal(benchErr)
				}
			}
		})
	}
}

func benchParallelStream(
	b *testing.B,
	engine, mode, sizeName string,
	n int,
	prepared parallelStreamMode,
	src []byte,
) {
	b.Run(engine+"/"+mode+"/"+sizeName+"/AutoXOR", func(b *testing.B) {
		dst := make([]byte, 0, len(src))
		b.SetBytes(int64(n))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchBytes, benchErr = prepared.XORKeyStream(dst[:0], src)
			if benchErr != nil {
				b.Fatal(benchErr)
			}
		}
	})
	for _, workers := range []int{2, 4, 8} {
		b.Run(engine+"/"+mode+"/"+sizeName+"/Manual"+itoaBench(workers)+"XOR", func(b *testing.B) {
			dst := make([]byte, 0, len(src))
			if configurable, ok := prepared.(benchWorkerConfigurable); ok {
				if err := configurable.SetWorkers(workers); err != nil {
					b.Fatal(err)
				}
				b.Cleanup(configurable.Close)
			}
			b.SetBytes(int64(n))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchBytes, benchErr = prepared.XORKeyStreamWithWorkers(dst[:0], src, workers)
				if benchErr != nil {
					b.Fatal(benchErr)
				}
			}
		})
	}
}

func BenchmarkFastPathVsGenericWrapper(b *testing.B) {
	key := testKey()
	for _, alg := range []struct {
		name string
		new  func() lowLevelBenchBlock
	}{
		{"GOST28147", func() lowLevelBenchBlock { return gost28147.NewCipher(key, gost28147.SboxDefault) }},
		{"Magma", func() lowLevelBenchBlock { return gost341264.NewCipher(key) }},
		{"Kuznechik", func() lowLevelBenchBlock { return gost3412128.NewCipher(key) }},
	} {
		block := alg.new()
		blockSize := block.BlockSize()
		generic := onlyBlock{block}
		iv := testIV(blockSize)
		for _, size := range benchSizes() {
			plaintext := testPlaintext(size.n)
			dst := make([]byte, size.n)
			state := newGenericBenchState(generic, blockSize)

			if size.n%blockSize == 0 {
				b.Run(alg.name+"/CBC/Fast/"+size.name, func(b *testing.B) {
					b.SetBytes(int64(size.n))
					b.ReportAllocs()
					for i := 0; i < b.N; i++ {
						block.EncryptCBC(dst, plaintext, iv)
					}
				})
				b.Run(alg.name+"/CBC/GenericWrapper/"+size.name, func(b *testing.B) {
					b.SetBytes(int64(size.n))
					b.ReportAllocs()
					for i := 0; i < b.N; i++ {
						state.encryptCBC(dst, plaintext, iv)
					}
				})
			}

			b.Run(alg.name+"/CFB/Fast/"+size.name, func(b *testing.B) {
				b.SetBytes(int64(size.n))
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					block.EncryptCFB(dst, plaintext, iv)
				}
			})
			b.Run(alg.name+"/CFB/GenericWrapper/"+size.name, func(b *testing.B) {
				b.SetBytes(int64(size.n))
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					state.encryptCFB(dst, plaintext, iv)
				}
			})
			b.Run(alg.name+"/OFB/Fast/"+size.name, func(b *testing.B) {
				b.SetBytes(int64(size.n))
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					block.XORKeyStreamOFB(dst, plaintext, iv)
				}
			})
			b.Run(alg.name+"/OFB/GenericWrapper/"+size.name, func(b *testing.B) {
				b.SetBytes(int64(size.n))
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					state.xorOFB(dst, plaintext, iv)
				}
			})
			b.Run(alg.name+"/CTR/Fast/"+size.name, func(b *testing.B) {
				var counter [16]byte
				b.SetBytes(int64(size.n))
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					copy(counter[:blockSize], iv)
					block.XORKeyStreamCTRCounter(dst, plaintext, counter[:blockSize])
				}
			})
			b.Run(alg.name+"/CTR/GenericWrapper/"+size.name, func(b *testing.B) {
				b.SetBytes(int64(size.n))
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					state.xorCTR(dst, plaintext, iv)
				}
			})
			b.Run(alg.name+"/MAC/Fast/"+size.name, func(b *testing.B) {
				tag := make([]byte, 0, blockSize)
				b.SetBytes(int64(size.n))
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					benchBytes = block.SumGOST3413MAC(tag[:0], plaintext, blockSize)
				}
			})
			b.Run(alg.name+"/MAC/GenericWrapper/"+size.name, func(b *testing.B) {
				tag := make([]byte, blockSize)
				b.SetBytes(int64(size.n))
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					state.sumMAC(tag, plaintext)
				}
			})
		}
	}
}

func BenchmarkPreparedReuseVsCreatePerCall(b *testing.B) {
	for _, engine := range benchEngines() {
		e := engine.newEngine()
		iv := testIV(engine.blockSize)
		for _, size := range benchSizes() {
			plaintext := testPlaintext(size.n)
			benchPreparedReuseVsCreateBlockMode(b, engine.name, "CBC", size, plaintext,
				func() benchMode { return mustMode(e.CBC(iv, modes.PaddingDefault)) })
			benchPreparedReuseVsCreateBlockMode(b, engine.name, "CFB", size, plaintext,
				func() benchMode { return mustMode(e.CFB(iv)) })
			benchPreparedReuseVsCreateBlockMode(b, engine.name, "OFB", size, plaintext,
				func() benchMode { return mustMode(e.OFB(iv)) })
			benchPreparedReuseVsCreateBlockMode(b, engine.name, "CTR", size, plaintext,
				func() benchMode { return mustMode(e.CTR(iv)) })
			benchPreparedReuseVsCreateMAC(b, engine.name, size, plaintext,
				func() *modes.MAC { return mustMode(e.MAC(engine.blockSize)) })
		}
	}
}

func benchHighLevelVsLowLevel(b *testing.B, name string, blockSize int, block lowLevelBenchBlock, engine testEngine) {
	for _, size := range benchSizes() {
		plaintext := testPlaintext(size.n)
		iv := testIV(blockSize)

		b.Run(name+"/CTR/LowLevel/"+size.name, func(b *testing.B) {
			dst := make([]byte, len(plaintext))
			var counter [16]byte
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				copy(counter[:blockSize], iv)
				block.XORKeyStreamCTRCounter(dst, plaintext, counter[:blockSize])
			}
		})
		b.Run(name+"/CTR/Modes/"+size.name, func(b *testing.B) {
			ctr := mustMode(engine.CTR(iv))
			dst := make([]byte, 0, len(plaintext))
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				benchBytes, benchErr = ctr.XORKeyStream(dst[:0], plaintext)
				if benchErr != nil {
					b.Fatal(benchErr)
				}
			}
		})

		if len(plaintext)%blockSize == 0 {
			b.Run(name+"/ECB/LowLevel/"+size.name, func(b *testing.B) {
				dst := make([]byte, len(plaintext))
				b.SetBytes(int64(size.n))
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					block.EncryptBlocks(dst, plaintext)
				}
			})
			b.Run(name+"/ECB/Modes/"+size.name, func(b *testing.B) {
				ecb := engine.ECB(modes.PaddingNone)
				dst := make([]byte, 0, len(plaintext))
				b.SetBytes(int64(size.n))
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					benchBytes, benchErr = ecb.Encrypt(dst[:0], plaintext)
					if benchErr != nil {
						b.Fatal(benchErr)
					}
				}
			})
			b.Run(name+"/CBC/LowLevel/"+size.name, func(b *testing.B) {
				dst := make([]byte, len(plaintext))
				b.SetBytes(int64(size.n))
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					block.EncryptCBC(dst, plaintext, iv)
				}
			})
			b.Run(name+"/CBC/Modes/"+size.name, func(b *testing.B) {
				cbc := mustMode(engine.CBC(iv, modes.PaddingNone))
				dst := make([]byte, 0, len(plaintext))
				b.SetBytes(int64(size.n))
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					benchBytes, benchErr = cbc.Encrypt(dst[:0], plaintext)
					if benchErr != nil {
						b.Fatal(benchErr)
					}
				}
			})
		}

		b.Run(name+"/CFB/LowLevel/"+size.name, func(b *testing.B) {
			dst := make([]byte, len(plaintext))
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				block.EncryptCFB(dst, plaintext, iv)
			}
		})
		b.Run(name+"/CFB/Modes/"+size.name, func(b *testing.B) {
			cfb := mustMode(engine.CFB(iv))
			dst := make([]byte, 0, len(plaintext))
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				benchBytes, benchErr = cfb.Encrypt(dst[:0], plaintext)
				if benchErr != nil {
					b.Fatal(benchErr)
				}
			}
		})
		b.Run(name+"/OFB/LowLevel/"+size.name, func(b *testing.B) {
			dst := make([]byte, len(plaintext))
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				block.XORKeyStreamOFB(dst, plaintext, iv)
			}
		})
		b.Run(name+"/OFB/Modes/"+size.name, func(b *testing.B) {
			ofb := mustMode(engine.OFB(iv))
			dst := make([]byte, 0, len(plaintext))
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				benchBytes, benchErr = ofb.XORKeyStream(dst[:0], plaintext)
				if benchErr != nil {
					b.Fatal(benchErr)
				}
			}
		})
		b.Run(name+"/MAC/LowLevel/"+size.name, func(b *testing.B) {
			dst := make([]byte, 0, blockSize)
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				benchBytes = block.SumGOST3413MAC(dst[:0], plaintext, blockSize)
			}
		})
		b.Run(name+"/MAC/Modes/"+size.name, func(b *testing.B) {
			mac := mustMode(engine.MAC(blockSize))
			dst := make([]byte, 0, blockSize)
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				benchBytes = mac.Sum(dst[:0], plaintext)
			}
		})
	}
}

func benchPreparedReuseVsCreateBlockMode(
	b *testing.B,
	engine string,
	mode string,
	size struct {
		name string
		n    int
	},
	plaintext []byte,
	newMode func() benchMode,
) {
	prepared := newMode()
	ciphertext, err := prepared.Encrypt(nil, plaintext)
	if err != nil {
		b.Fatal(err)
	}
	b.Run(engine+"/"+mode+"/"+size.name+"/Reuse", func(b *testing.B) {
		dst := make([]byte, 0, len(ciphertext))
		b.SetBytes(int64(size.n))
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			benchBytes, benchErr = prepared.Encrypt(dst[:0], plaintext)
			if benchErr != nil {
				b.Fatal(benchErr)
			}
		}
	})
	b.Run(engine+"/"+mode+"/"+size.name+"/CreateEachCall", func(b *testing.B) {
		dst := make([]byte, 0, len(ciphertext))
		b.SetBytes(int64(size.n))
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			benchBytes, benchErr = newMode().Encrypt(dst[:0], plaintext)
			if benchErr != nil {
				b.Fatal(benchErr)
			}
		}
	})
}

func benchPreparedReuseVsCreateMAC(
	b *testing.B,
	engine string,
	size struct {
		name string
		n    int
	},
	plaintext []byte,
	newMAC func() *modes.MAC,
) {
	mac := newMAC()
	b.Run(engine+"/MAC/"+size.name+"/Reuse", func(b *testing.B) {
		dst := make([]byte, 0, 16)
		b.SetBytes(int64(size.n))
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			benchBytes = mac.Sum(dst[:0], plaintext)
		}
	})
	b.Run(engine+"/MAC/"+size.name+"/CreateEachCall", func(b *testing.B) {
		dst := make([]byte, 0, 16)
		b.SetBytes(int64(size.n))
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			benchBytes = newMAC().Sum(dst[:0], plaintext)
		}
	})
}

func benchPreparedBlockMode(b *testing.B, engine, mode, sizeName string, n int, prepared benchMode, plaintext []byte) {
	ciphertext, err := prepared.Encrypt(nil, plaintext)
	if err != nil {
		b.Fatal(err)
	}
	b.Run(engine+"/"+mode+"/"+sizeName+"/Encrypt", func(b *testing.B) {
		dst := make([]byte, 0, len(ciphertext))
		b.SetBytes(int64(n))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchBytes, benchErr = prepared.Encrypt(dst[:0], plaintext)
			if benchErr != nil {
				b.Fatal(benchErr)
			}
		}
	})
	b.Run(engine+"/"+mode+"/"+sizeName+"/Decrypt", func(b *testing.B) {
		dst := make([]byte, 0, len(ciphertext))
		b.SetBytes(int64(n))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchBytes, benchErr = prepared.Decrypt(dst[:0], ciphertext)
			if benchErr != nil {
				b.Fatal(benchErr)
			}
		}
	})
}

func benchPreparedStream(b *testing.B, engine, mode, sizeName string, n int, prepared benchStream, plaintext []byte) {
	b.Run(engine+"/"+mode+"/"+sizeName, func(b *testing.B) {
		dst := make([]byte, 0, len(plaintext))
		b.SetBytes(int64(n))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchBytes, benchErr = prepared.XORKeyStream(dst[:0], plaintext)
			if benchErr != nil {
				b.Fatal(benchErr)
			}
		}
	})
}

func benchBlockTo(b *testing.B, engine, mode string, prepared interface {
	EncryptTo([]byte, []byte) ([]byte, error)
	DecryptTo([]byte, []byte) ([]byte, error)
	Encrypt([]byte, []byte) ([]byte, error)
}, plaintext []byte) {
	ciphertext, err := prepared.Encrypt(nil, plaintext)
	if err != nil {
		b.Fatal(err)
	}
	b.Run(engine+"/"+mode+"/EncryptTo", func(b *testing.B) {
		dst := make([]byte, len(ciphertext))
		b.SetBytes(int64(len(plaintext)))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchBytes, benchErr = prepared.EncryptTo(dst, plaintext)
			if benchErr != nil {
				b.Fatal(benchErr)
			}
		}
	})
	b.Run(engine+"/"+mode+"/DecryptTo", func(b *testing.B) {
		dst := make([]byte, len(ciphertext))
		b.SetBytes(int64(len(plaintext)))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchBytes, benchErr = prepared.DecryptTo(dst, ciphertext)
			if benchErr != nil {
				b.Fatal(benchErr)
			}
		}
	})
}

func benchStreamTo(b *testing.B, engine, mode string, prepared interface {
	XORKeyStreamTo([]byte, []byte) ([]byte, error)
}, plaintext []byte) {
	dst := make([]byte, len(plaintext))
	b.Run(engine+"/"+mode+"/XORKeyStreamTo", func(b *testing.B) {
		b.SetBytes(int64(len(plaintext)))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchBytes, benchErr = prepared.XORKeyStreamTo(dst, plaintext)
			if benchErr != nil {
				b.Fatal(benchErr)
			}
		}
	})
}

func benchPreparedMGM(b *testing.B, engine, sizeName string, n int, aead *modes.MGM, nonce, plaintext, ad []byte) {
	sealed, err := aead.Seal(nil, nonce, plaintext, ad)
	if err != nil {
		b.Fatal(err)
	}
	b.Run(engine+"/MGM/"+sizeName+"/Seal", func(b *testing.B) {
		dst := make([]byte, 0, len(sealed))
		b.SetBytes(int64(n))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchBytes, benchErr = aead.Seal(dst[:0], nonce, plaintext, ad)
			if benchErr != nil {
				b.Fatal(benchErr)
			}
		}
	})
	b.Run(engine+"/MGM/"+sizeName+"/Open", func(b *testing.B) {
		dst := make([]byte, 0, len(plaintext))
		b.SetBytes(int64(n))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchBytes, benchErr = aead.Open(dst[:0], nonce, sealed, ad)
			if benchErr != nil {
				b.Fatal(benchErr)
			}
		}
	})
}

func benchEngines() []benchEngine {
	return []benchEngine{
		{
			name:      "GOST28147",
			blockSize: gost28147.BlockSize,
			newEngine: func() testEngine {
				return modes.MustGOST28147Default(testKey())
			},
		},
		{
			name:      "Kuznechik",
			blockSize: gost3412128.BlockSize,
			newEngine: func() testEngine {
				return modes.MustKuznechik(testKey())
			},
		},
		{
			name:      "Magma",
			blockSize: gost341264.BlockSize,
			newEngine: func() testEngine {
				return modes.MustMagma(testKey())
			},
		},
	}
}

func benchSizes() []struct {
	name string
	n    int
} {
	return []struct {
		name string
		n    int
	}{
		{"8B", 8},
		{"16B", 16},
		{"32B", 32},
		{"64B", 64},
		{"1KiB", 1024},
		{"16KiB", 16 * 1024},
		{"1MiB", 1024 * 1024},
	}
}

func parallelBenchSizes() []struct {
	name string
	n    int
} {
	return []struct {
		name string
		n    int
	}{
		{"16B", 16},
		{"64KiB", 64 * 1024},
		{"1MiB", 1024 * 1024},
		{"16MiB", 16 * 1024 * 1024},
	}
}

func itoaBench(n int) string {
	return strconv.Itoa(n)
}

type genericBenchState struct {
	block     cipher.Block
	blockSize int
	prev      [16]byte
	register  [16]byte
	gamma     [16]byte
	tmp       [16]byte
	state     [16]byte
	last      [16]byte
	padded    [16]byte
	k1        [16]byte
	k2        [16]byte
}

func newGenericBenchState(block cipher.Block, blockSize int) *genericBenchState {
	s := &genericBenchState{block: block, blockSize: blockSize}
	block.Encrypt(s.tmp[:blockSize], s.state[:blockSize])
	benchDoubleSubkeyInto(s.k1[:blockSize], s.tmp[:blockSize])
	benchDoubleSubkeyInto(s.k2[:blockSize], s.k1[:blockSize])
	return s
}

func (s *genericBenchState) encryptCBC(dst, src, iv []byte) {
	copy(s.prev[:s.blockSize], iv)
	for len(src) >= s.blockSize {
		xorBenchBlock(s.tmp[:s.blockSize], src[:s.blockSize], s.prev[:s.blockSize], s.blockSize)
		s.block.Encrypt(dst[:s.blockSize], s.tmp[:s.blockSize])
		copy(s.prev[:s.blockSize], dst[:s.blockSize])
		dst = dst[s.blockSize:]
		src = src[s.blockSize:]
	}
}

func (s *genericBenchState) encryptCFB(dst, src, iv []byte) {
	copy(s.register[:s.blockSize], iv)
	for len(src) > 0 {
		s.block.Encrypt(s.gamma[:s.blockSize], s.register[:s.blockSize])
		n := min(s.blockSize, len(src))
		xorBytes(dst[:n], src[:n], s.gamma[:n])
		copy(s.register[:s.blockSize-n], s.register[n:s.blockSize])
		copy(s.register[s.blockSize-n:s.blockSize], dst[:n])
		dst = dst[n:]
		src = src[n:]
	}
}

func (s *genericBenchState) xorOFB(dst, src, iv []byte) {
	copy(s.register[:s.blockSize], iv)
	for len(src) > 0 {
		s.block.Encrypt(s.gamma[:s.blockSize], s.register[:s.blockSize])
		n := min(s.blockSize, len(src))
		xorBytes(dst[:n], src[:n], s.gamma[:n])
		copy(s.register[:s.blockSize-n], s.register[n:s.blockSize])
		copy(s.register[s.blockSize-n:s.blockSize], s.gamma[:n])
		dst = dst[n:]
		src = src[n:]
	}
}

func (s *genericBenchState) xorCTR(dst, src, iv []byte) {
	clear(s.register[:s.blockSize])
	copy(s.register[:s.blockSize], iv)
	for len(src) > 0 {
		s.block.Encrypt(s.gamma[:s.blockSize], s.register[:s.blockSize])
		n := min(s.blockSize, len(src))
		xorBytes(dst[:n], src[:n], s.gamma[:n])
		incHalf(s.register[s.blockSize/2 : s.blockSize])
		dst = dst[n:]
		src = src[n:]
	}
}

func (s *genericBenchState) sumMAC(dst, data []byte) {
	fullBlocks := len(data) / s.blockSize
	clear(s.state[:s.blockSize])
	clear(s.last[:s.blockSize])
	if len(data) > 0 && len(data)%s.blockSize == 0 {
		fullBlocks--
		xorBenchBlock(s.last[:s.blockSize], data[len(data)-s.blockSize:], s.k1[:s.blockSize], s.blockSize)
	} else {
		clear(s.padded[:s.blockSize])
		copy(s.padded[:s.blockSize], data[fullBlocks*s.blockSize:])
		s.padded[len(data)-fullBlocks*s.blockSize] = 0x80
		xorBenchBlock(s.last[:s.blockSize], s.padded[:s.blockSize], s.k2[:s.blockSize], s.blockSize)
	}
	for offset := 0; offset < fullBlocks*s.blockSize; offset += s.blockSize {
		xorBenchBlock(s.state[:s.blockSize], s.state[:s.blockSize], data[offset:offset+s.blockSize], s.blockSize)
		s.block.Encrypt(s.state[:s.blockSize], s.state[:s.blockSize])
	}
	xorBenchBlock(s.state[:s.blockSize], s.state[:s.blockSize], s.last[:s.blockSize], s.blockSize)
	s.block.Encrypt(s.state[:s.blockSize], s.state[:s.blockSize])
	copy(dst, s.state[:s.blockSize])
}

func xorBenchBlock(dst, a, b []byte, blockSize int) {
	switch blockSize {
	case 8:
		v := load64ForBench(a) ^ load64ForBench(b)
		store64ForBench(dst, v)
	case 16:
		v0 := load64ForBench(a[:8]) ^ load64ForBench(b[:8])
		v1 := load64ForBench(a[8:16]) ^ load64ForBench(b[8:16])
		store64ForBench(dst[:8], v0)
		store64ForBench(dst[8:16], v1)
	default:
		xorBytes(dst, a, b)
	}
}

func load64ForBench(b []byte) uint64 {
	_ = b[7]
	return uint64(b[0])<<56 |
		uint64(b[1])<<48 |
		uint64(b[2])<<40 |
		uint64(b[3])<<32 |
		uint64(b[4])<<24 |
		uint64(b[5])<<16 |
		uint64(b[6])<<8 |
		uint64(b[7])
}

func store64ForBench(b []byte, v uint64) {
	_ = b[7]
	b[0] = byte(v >> 56)
	b[1] = byte(v >> 48)
	b[2] = byte(v >> 40)
	b[3] = byte(v >> 32)
	b[4] = byte(v >> 24)
	b[5] = byte(v >> 16)
	b[6] = byte(v >> 8)
	b[7] = byte(v)
}

func benchDoubleSubkeyInto(out, k []byte) {
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
		}
	}
}
