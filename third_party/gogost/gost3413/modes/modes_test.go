package modes_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"gitverse.ru/uzer_007/gogost/v3/gost28147"
	"gitverse.ru/uzer_007/gogost/v3/gost3412128"
	"gitverse.ru/uzer_007/gogost/v3/gost341264"
	"gitverse.ru/uzer_007/gogost/v3/gost3413/modes"
)

type testEngine interface {
	ECB(padding modes.Padding) *modes.ECB
	CBC(iv []byte, padding modes.Padding) (*modes.CBC, error)
	CFB(iv []byte) (*modes.CFB, error)
	CFBN(iv []byte, segmentSize, registerSize int) (*modes.CFB, error)
	OFB(iv []byte) (*modes.OFB, error)
	OFBN(iv []byte, segmentSize, registerSize int) (*modes.OFB, error)
	CTR(iv []byte) (*modes.CTR, error)
	CTRACPKM(iv []byte, sectionSize int) (*modes.CTRACPKM, error)
	MAC(tagSize int) (*modes.MAC, error)
	MGM(tagSize int) (*modes.MGM, error)
}

func testKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func testIV(size int) []byte {
	iv := make([]byte, size)
	for i := range iv {
		iv[i] = byte(i + 1)
	}
	return iv
}

func testPlaintext(size int) []byte {
	plaintext := make([]byte, size)
	for i := range plaintext {
		plaintext[i] = byte(17 + i*31)
	}
	return plaintext
}

func newTestEngine(t *testing.T, alg modes.Algorithm) (testEngine, int) {
	t.Helper()
	switch alg {
	case modes.AlgorithmGOST28147:
		e, err := modes.NewGOST28147Default(testKey())
		if err != nil {
			t.Fatal(err)
		}
		return e, gost28147.BlockSize
	case modes.AlgorithmMagma:
		e, err := modes.NewMagma(testKey())
		if err != nil {
			t.Fatal(err)
		}
		return e, gost341264.BlockSize
	case modes.AlgorithmKuznechik:
		e, err := modes.NewKuznechik(testKey())
		if err != nil {
			t.Fatal(err)
		}
		return e, gost3412128.BlockSize
	default:
		t.Fatal("unknown algorithm")
		return nil, 0
	}
}

func TestRoundTrip(t *testing.T) {
	for _, alg := range []struct {
		name      string
		algorithm modes.Algorithm
	}{
		{"GOST28147", modes.AlgorithmGOST28147},
		{"Magma", modes.AlgorithmMagma},
		{"Kuznechik", modes.AlgorithmKuznechik},
	} {
		engine, blockSize := newTestEngine(t, alg.algorithm)
		lengths := []int{0, 1, blockSize - 1, blockSize, blockSize + 1, 2*blockSize + 3}
		for _, mode := range []modes.Mode{
			modes.ModeECB,
			modes.ModeCBC,
			modes.ModeCFB,
			modes.ModeOFB,
			modes.ModeCTR,
			modes.ModeCTRACPKM,
			modes.ModeMGM,
		} {
			for _, length := range lengths {
				plaintext := testPlaintext(length)
				ciphertext, decrypted, err := roundTrip(engine, mode, blockSize, plaintext)
				if err != nil {
					t.Fatalf("%s/%v/%d: %v", alg.name, mode, length, err)
				}
				if !bytes.Equal(decrypted, plaintext) {
					t.Fatalf("%s/%v/%d round-trip mismatch", alg.name, mode, length)
				}
				if isStreamMode(mode) && len(ciphertext) != len(plaintext) {
					t.Fatalf("%s/%v/%d ciphertext length=%d", alg.name, mode, length, len(ciphertext))
				}
			}
		}
	}
}

func TestToMethodsMatchAppendAPI(t *testing.T) {
	for _, alg := range []struct {
		name      string
		algorithm modes.Algorithm
	}{
		{"GOST28147", modes.AlgorithmGOST28147},
		{"Magma", modes.AlgorithmMagma},
		{"Kuznechik", modes.AlgorithmKuznechik},
	} {
		engine, blockSize := newTestEngine(t, alg.algorithm)
		iv := testIV(blockSize)
		plaintext := testPlaintext(3*blockSize + 5)
		aligned := testPlaintext(4 * blockSize)

		assertBlockToMethods(t, alg.name+"/ECB", engine.ECB(modes.PaddingDefault), plaintext)
		assertBlockToMethods(t, alg.name+"/ECB/PaddingNone", engine.ECB(modes.PaddingNone), aligned)
		assertBlockToMethods(t, alg.name+"/CBC", mustMode(engine.CBC(iv, modes.PaddingDefault)), plaintext)
		assertBlockToMethods(t, alg.name+"/CBC/PaddingNone", mustMode(engine.CBC(iv, modes.PaddingNone)), aligned)
		assertBlockToMethods(t, alg.name+"/CFB", mustMode(engine.CFB(iv)), plaintext)
		assertStreamToMethods(t, alg.name+"/OFB", mustMode(engine.OFB(iv)), plaintext)
		assertStreamToMethods(t, alg.name+"/CTR", mustMode(engine.CTR(iv)), plaintext)
		assertStreamToMethods(t, alg.name+"/CTRACPKM", mustMode(engine.CTRACPKM(iv, modes.DefaultACPKMSectionSize)), plaintext)
	}
}

func TestParallelDecryptFastPathsMatchInPlaceFallback(t *testing.T) {
	for _, alg := range []struct {
		name      string
		algorithm modes.Algorithm
	}{
		{"GOST28147", modes.AlgorithmGOST28147},
		{"Magma", modes.AlgorithmMagma},
		{"Kuznechik", modes.AlgorithmKuznechik},
	} {
		engine, blockSize := newTestEngine(t, alg.algorithm)
		iv := testIV(blockSize)
		aligned := testPlaintext(1024)

		cbc := mustMode(engine.CBC(iv, modes.PaddingNone))
		cbcCiphertext := mustEncrypt(t, cbc, aligned)
		got := make([]byte, len(cbcCiphertext))
		gotPlain, err := cbc.DecryptTo(got, cbcCiphertext)
		if err != nil {
			t.Fatalf("%s/CBC out-of-place decrypt: %v", alg.name, err)
		}
		inPlace := append([]byte(nil), cbcCiphertext...)
		inPlacePlain, err := cbc.DecryptTo(inPlace, inPlace)
		if err != nil {
			t.Fatalf("%s/CBC in-place decrypt: %v", alg.name, err)
		}
		if !bytes.Equal(gotPlain, aligned) || !bytes.Equal(inPlacePlain, aligned) {
			t.Fatalf("%s/CBC decrypt mismatch", alg.name)
		}

		cfb := mustMode(engine.CFB(iv))
		plaintext := testPlaintext(1024 + blockSize - 1)
		cfbCiphertext := mustEncrypt(t, cfb, plaintext)
		got = make([]byte, len(cfbCiphertext))
		gotPlain, err = cfb.DecryptTo(got, cfbCiphertext)
		if err != nil {
			t.Fatalf("%s/CFB out-of-place decrypt: %v", alg.name, err)
		}
		inPlace = append([]byte(nil), cfbCiphertext...)
		inPlacePlain, err = cfb.DecryptTo(inPlace, inPlace)
		if err != nil {
			t.Fatalf("%s/CFB in-place decrypt: %v", alg.name, err)
		}
		if !bytes.Equal(gotPlain, plaintext) || !bytes.Equal(inPlacePlain, plaintext) {
			t.Fatalf("%s/CFB decrypt mismatch", alg.name)
		}
	}
}

type blockToMode interface {
	Encrypt([]byte, []byte) ([]byte, error)
	Decrypt([]byte, []byte) ([]byte, error)
	EncryptTo([]byte, []byte) ([]byte, error)
	DecryptTo([]byte, []byte) ([]byte, error)
}

type streamToMode interface {
	Encrypt([]byte, []byte) ([]byte, error)
	Decrypt([]byte, []byte) ([]byte, error)
	EncryptTo([]byte, []byte) ([]byte, error)
	DecryptTo([]byte, []byte) ([]byte, error)
	XORKeyStream([]byte, []byte) ([]byte, error)
	XORKeyStreamTo([]byte, []byte) ([]byte, error)
}

func assertBlockToMethods(t *testing.T, name string, mode blockToMode, plaintext []byte) {
	t.Helper()
	ciphertext, err := mode.Encrypt(nil, plaintext)
	if err != nil {
		t.Fatalf("%s append encrypt: %v", name, err)
	}
	dst := make([]byte, len(ciphertext))
	gotCiphertext, err := mode.EncryptTo(dst, plaintext)
	if err != nil {
		t.Fatalf("%s to encrypt: %v", name, err)
	}
	if !bytes.Equal(gotCiphertext, ciphertext) {
		t.Fatalf("%s EncryptTo mismatch", name)
	}
	decrypted, err := mode.Decrypt(nil, ciphertext)
	if err != nil {
		t.Fatalf("%s append decrypt: %v", name, err)
	}
	dst = make([]byte, len(ciphertext))
	gotPlaintext, err := mode.DecryptTo(dst, ciphertext)
	if err != nil {
		t.Fatalf("%s to decrypt: %v", name, err)
	}
	if !bytes.Equal(gotPlaintext, decrypted) || !bytes.Equal(gotPlaintext, plaintext) {
		t.Fatalf("%s DecryptTo mismatch", name)
	}
}

func assertStreamToMethods(t *testing.T, name string, mode streamToMode, plaintext []byte) {
	t.Helper()
	ciphertext, err := mode.XORKeyStream(nil, plaintext)
	if err != nil {
		t.Fatalf("%s append stream: %v", name, err)
	}
	dst := make([]byte, len(plaintext))
	gotCiphertext, err := mode.XORKeyStreamTo(dst, plaintext)
	if err != nil {
		t.Fatalf("%s to stream: %v", name, err)
	}
	if !bytes.Equal(gotCiphertext, ciphertext) {
		t.Fatalf("%s XORKeyStreamTo mismatch", name)
	}
	decrypted, err := mode.DecryptTo(dst, ciphertext)
	if err != nil {
		t.Fatalf("%s to decrypt: %v", name, err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("%s DecryptTo mismatch", name)
	}
	encrypted, err := mode.EncryptTo(dst, plaintext)
	if err != nil {
		t.Fatalf("%s to encrypt: %v", name, err)
	}
	if !bytes.Equal(encrypted, ciphertext) {
		t.Fatalf("%s EncryptTo mismatch", name)
	}
}

func mustEncrypt(t *testing.T, mode blockToMode, plaintext []byte) []byte {
	t.Helper()
	ciphertext, err := mode.Encrypt(nil, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	return ciphertext
}

func roundTrip(engine testEngine, mode modes.Mode, blockSize int, plaintext []byte) ([]byte, []byte, error) {
	iv := testIV(blockSize)
	switch mode {
	case modes.ModeECB:
		c := engine.ECB(modes.PaddingDefault)
		ciphertext, err := c.Encrypt(nil, plaintext)
		if err != nil {
			return nil, nil, err
		}
		decrypted, err := c.Decrypt(nil, ciphertext)
		return ciphertext, decrypted, err
	case modes.ModeCBC:
		c, err := engine.CBC(iv, modes.PaddingDefault)
		if err != nil {
			return nil, nil, err
		}
		ciphertext, err := c.Encrypt(nil, plaintext)
		if err != nil {
			return nil, nil, err
		}
		decrypted, err := c.Decrypt(nil, ciphertext)
		return ciphertext, decrypted, err
	case modes.ModeCFB:
		c, err := engine.CFB(iv)
		if err != nil {
			return nil, nil, err
		}
		ciphertext, err := c.Encrypt(nil, plaintext)
		if err != nil {
			return nil, nil, err
		}
		decrypted, err := c.Decrypt(nil, ciphertext)
		return ciphertext, decrypted, err
	case modes.ModeOFB:
		c, err := engine.OFB(iv)
		if err != nil {
			return nil, nil, err
		}
		ciphertext, err := c.Encrypt(nil, plaintext)
		if err != nil {
			return nil, nil, err
		}
		decrypted, err := c.Decrypt(nil, ciphertext)
		return ciphertext, decrypted, err
	case modes.ModeCTR:
		c, err := engine.CTR(iv)
		if err != nil {
			return nil, nil, err
		}
		ciphertext, err := c.Encrypt(nil, plaintext)
		if err != nil {
			return nil, nil, err
		}
		decrypted, err := c.Decrypt(nil, ciphertext)
		return ciphertext, decrypted, err
	case modes.ModeCTRACPKM:
		c, err := engine.CTRACPKM(iv, modes.DefaultACPKMSectionSize)
		if err != nil {
			return nil, nil, err
		}
		ciphertext, err := c.Encrypt(nil, plaintext)
		if err != nil {
			return nil, nil, err
		}
		decrypted, err := c.Decrypt(nil, ciphertext)
		return ciphertext, decrypted, err
	case modes.ModeMGM:
		c, err := engine.MGM(0)
		if err != nil {
			return nil, nil, err
		}
		ciphertext, err := c.Seal(nil, iv, plaintext, []byte("metadata"))
		if err != nil {
			return nil, nil, err
		}
		decrypted, err := c.Open(nil, iv, ciphertext, []byte("metadata"))
		return ciphertext, decrypted, err
	default:
		return nil, nil, modes.ErrInvalidMode
	}
}

func TestECBKnownVectors(t *testing.T) {
	tests := []struct {
		name       string
		algorithm  modes.Algorithm
		key        string
		plaintext  string
		ciphertext string
	}{
		{
			name:       "Kuznechik",
			algorithm:  modes.AlgorithmKuznechik,
			key:        "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
			plaintext:  "1122334455667700ffeeddccbbaa9988",
			ciphertext: "7f679d90bebc24305a468d42b9d4edcd",
		},
		{
			name:       "Magma",
			algorithm:  modes.AlgorithmMagma,
			key:        "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
			plaintext:  "fedcba9876543210",
			ciphertext: "4ee901e5c2d8ca3d",
		},
	}
	for _, tc := range tests {
		key, _ := hex.DecodeString(tc.key)
		plaintext, _ := hex.DecodeString(tc.plaintext)
		want, _ := hex.DecodeString(tc.ciphertext)
		engine := newEngineForKey(t, tc.algorithm, key)
		got, err := engine.ECB(modes.PaddingNone).Encrypt(nil, plaintext)
		if err != nil {
			t.Fatalf("%s encrypt: %v", tc.name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s ECB = %x, want %x", tc.name, got, want)
		}
	}
}

func newEngineForKey(t *testing.T, alg modes.Algorithm, key []byte) testEngine {
	t.Helper()
	switch alg {
	case modes.AlgorithmMagma:
		e, err := modes.NewMagma(key)
		if err != nil {
			t.Fatal(err)
		}
		return e
	case modes.AlgorithmGOST28147:
		e, err := modes.NewGOST28147Default(key)
		if err != nil {
			t.Fatal(err)
		}
		return e
	case modes.AlgorithmKuznechik:
		e, err := modes.NewKuznechik(key)
		if err != nil {
			t.Fatal(err)
		}
		return e
	default:
		t.Fatal("unknown algorithm")
		return nil
	}
}

func TestGOST3413MagmaOFBVector(t *testing.T) {
	key, _ := hex.DecodeString("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	iv, _ := hex.DecodeString("1234567890abcdef234567890abcdef1")
	plaintext, _ := hex.DecodeString(
		"92def06b3c130a59" +
			"db54c704f8189d20" +
			"4a98fb2e67a8024c" +
			"8912409b17b57e41",
	)
	want, _ := hex.DecodeString(
		"db37e0e266903c83" +
			"0d46644c1f9a089c" +
			"a0f83062430e327e" +
			"c824efb8bd4fdb05",
	)
	engine, err := modes.NewMagma(key)
	if err != nil {
		t.Fatal(err)
	}
	ofb, err := engine.OFBN(iv, gost341264.BlockSize, 2*gost341264.BlockSize)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ofb.Encrypt(nil, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("OFB ciphertext=%x, want %x", got, want)
	}
	decrypted, err := ofb.Decrypt(nil, got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("OFB decrypt mismatch")
	}
}

func TestCTRHalfBlockIV(t *testing.T) {
	engine, err := modes.NewKuznechik(testKey())
	if err != nil {
		t.Fatal(err)
	}
	ctr, err := engine.CTR(testIV(gost3412128.BlockSize / 2))
	if err != nil {
		t.Fatal(err)
	}
	plaintext := testPlaintext(2*gost3412128.BlockSize + 3)
	ciphertext, err := ctr.Encrypt(nil, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := ctr.Decrypt(nil, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("half-block IV CTR round-trip mismatch")
	}
}

func TestCTRACPKMPrecompute(t *testing.T) {
	for _, alg := range []struct {
		name      string
		algorithm modes.Algorithm
	}{
		{"GOST28147", modes.AlgorithmGOST28147},
		{"Magma", modes.AlgorithmMagma},
		{"Kuznechik", modes.AlgorithmKuznechik},
	} {
		engine, blockSize := newTestEngine(t, alg.algorithm)
		iv := testIV(blockSize)
		plaintext := testPlaintext(3*modes.DefaultACPKMSectionSize + blockSize + 1)

		cold := mustMode(engine.CTRACPKM(iv, modes.DefaultACPKMSectionSize))
		want, err := cold.Encrypt(nil, plaintext)
		if err != nil {
			t.Fatalf("%s cold encrypt: %v", alg.name, err)
		}

		warm := mustMode(engine.CTRACPKM(iv, modes.DefaultACPKMSectionSize))
		if err := warm.PrecomputeSections(len(plaintext)); err != nil {
			t.Fatalf("%s precompute: %v", alg.name, err)
		}
		got, err := warm.Encrypt(nil, plaintext)
		if err != nil {
			t.Fatalf("%s warm encrypt: %v", alg.name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s precomputed CTR-ACPKM mismatch", alg.name)
		}
		if err := warm.PrecomputeSections(-1); !errors.Is(err, modes.ErrInvalidInput) {
			t.Fatalf("%s negative precompute error=%v", alg.name, err)
		}
	}
}

func TestManualWorkersMatchSequential(t *testing.T) {
	for _, alg := range []struct {
		name      string
		algorithm modes.Algorithm
	}{
		{"GOST28147", modes.AlgorithmGOST28147},
		{"Magma", modes.AlgorithmMagma},
		{"Kuznechik", modes.AlgorithmKuznechik},
	} {
		engine, blockSize := newTestEngine(t, alg.algorithm)
		iv := testIV(blockSize)
		streamPlaintext := testPlaintext(2*parallelTestSize + blockSize + 3)
		aligned := testPlaintext(2 * parallelTestSize)

		ecb := engine.ECB(modes.PaddingNone)
		want, err := ecb.Encrypt(nil, aligned)
		if err != nil {
			t.Fatalf("%s/ECB encrypt: %v", alg.name, err)
		}
		for _, workers := range []int{2, 3, 4} {
			got, err := ecb.EncryptWithWorkers(nil, aligned, workers)
			if err != nil {
				t.Fatalf("%s/ECB EncryptWithWorkers/%d: %v", alg.name, workers, err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("%s/ECB EncryptWithWorkers/%d mismatch", alg.name, workers)
			}
			plain, err := ecb.DecryptWithWorkers(nil, want, workers)
			if err != nil {
				t.Fatalf("%s/ECB DecryptWithWorkers/%d: %v", alg.name, workers, err)
			}
			if !bytes.Equal(plain, aligned) {
				t.Fatalf("%s/ECB DecryptWithWorkers/%d mismatch", alg.name, workers)
			}
		}
		if _, err := ecb.EncryptWithWorkers(nil, aligned, 1); !errors.Is(err, modes.ErrInvalidInput) {
			t.Fatalf("%s/ECB workers=1 error=%v", alg.name, err)
		}

		cbc := mustMode(engine.CBC(iv, modes.PaddingNone))
		want, err = cbc.Encrypt(nil, aligned)
		if err != nil {
			t.Fatalf("%s/CBC encrypt: %v", alg.name, err)
		}
		for _, workers := range []int{2, 3, 4} {
			gotCiphertext, err := cbc.EncryptWithWorkers(nil, aligned, workers)
			if err != nil {
				t.Fatalf("%s/CBC EncryptWithWorkers/%d: %v", alg.name, workers, err)
			}
			if !bytes.Equal(gotCiphertext, want) {
				t.Fatalf("%s/CBC EncryptWithWorkers/%d mismatch", alg.name, workers)
			}
			got, err := cbc.DecryptWithWorkers(nil, want, workers)
			if err != nil {
				t.Fatalf("%s/CBC DecryptWithWorkers/%d: %v", alg.name, workers, err)
			}
			if !bytes.Equal(got, aligned) {
				t.Fatalf("%s/CBC DecryptWithWorkers/%d mismatch", alg.name, workers)
			}
		}

		cfb := mustMode(engine.CFB(iv))
		want, err = cfb.Encrypt(nil, streamPlaintext)
		if err != nil {
			t.Fatalf("%s/CFB encrypt: %v", alg.name, err)
		}
		for _, workers := range []int{2, 3, 4} {
			gotCiphertext, err := cfb.EncryptWithWorkers(nil, streamPlaintext, workers)
			if err != nil {
				t.Fatalf("%s/CFB EncryptWithWorkers/%d: %v", alg.name, workers, err)
			}
			if !bytes.Equal(gotCiphertext, want) {
				t.Fatalf("%s/CFB EncryptWithWorkers/%d mismatch", alg.name, workers)
			}
			got, err := cfb.DecryptWithWorkers(nil, want, workers)
			if err != nil {
				t.Fatalf("%s/CFB DecryptWithWorkers/%d: %v", alg.name, workers, err)
			}
			if !bytes.Equal(got, streamPlaintext) {
				t.Fatalf("%s/CFB DecryptWithWorkers/%d mismatch", alg.name, workers)
			}
		}

		ofb := mustMode(engine.OFB(iv))
		want, err = ofb.XORKeyStream(nil, streamPlaintext)
		if err != nil {
			t.Fatalf("%s/OFB encrypt: %v", alg.name, err)
		}
		for _, workers := range []int{2, 3, 4} {
			got, err := ofb.XORKeyStreamWithWorkers(nil, streamPlaintext, workers)
			if err != nil {
				t.Fatalf("%s/OFB XORKeyStreamWithWorkers/%d: %v", alg.name, workers, err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("%s/OFB XORKeyStreamWithWorkers/%d mismatch", alg.name, workers)
			}
		}
		if _, err := ofb.XORKeyStreamWithWorkers(nil, streamPlaintext, 1); !errors.Is(err, modes.ErrInvalidInput) {
			t.Fatalf("%s/OFB workers=1 error=%v", alg.name, err)
		}

		ctr := mustMode(engine.CTR(iv))
		want, err = ctr.XORKeyStream(nil, streamPlaintext)
		if err != nil {
			t.Fatalf("%s/CTR encrypt: %v", alg.name, err)
		}
		for _, workers := range []int{2, 3, 4} {
			got, err := ctr.XORKeyStreamWithWorkers(nil, streamPlaintext, workers)
			if err != nil {
				t.Fatalf("%s/CTR XORKeyStreamWithWorkers/%d: %v", alg.name, workers, err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("%s/CTR XORKeyStreamWithWorkers/%d mismatch", alg.name, workers)
			}
			plain, err := ctr.XORKeyStreamWithWorkers(nil, want, workers)
			if err != nil {
				t.Fatalf("%s/CTR decrypt/%d: %v", alg.name, workers, err)
			}
			if !bytes.Equal(plain, streamPlaintext) {
				t.Fatalf("%s/CTR decrypt/%d mismatch", alg.name, workers)
			}
		}

		acpkm := mustMode(engine.CTRACPKM(iv, modes.DefaultACPKMSectionSize))
		want, err = acpkm.XORKeyStream(nil, streamPlaintext)
		if err != nil {
			t.Fatalf("%s/CTR-ACPKM encrypt: %v", alg.name, err)
		}
		for _, workers := range []int{2, 3, 4} {
			got, err := acpkm.XORKeyStreamWithWorkers(nil, streamPlaintext, workers)
			if err != nil {
				t.Fatalf("%s/CTR-ACPKM XORKeyStreamWithWorkers/%d: %v", alg.name, workers, err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("%s/CTR-ACPKM XORKeyStreamWithWorkers/%d mismatch", alg.name, workers)
			}
		}
	}
}

func TestPersistentWorkersMatchSequential(t *testing.T) {
	for _, alg := range []struct {
		name      string
		algorithm modes.Algorithm
	}{
		{"GOST28147", modes.AlgorithmGOST28147},
		{"Magma", modes.AlgorithmMagma},
		{"Kuznechik", modes.AlgorithmKuznechik},
	} {
		engine, blockSize := newTestEngine(t, alg.algorithm)
		iv := testIV(blockSize)
		aligned := testPlaintext(2 * parallelTestSize)
		streamPlaintext := testPlaintext(2*parallelTestSize + blockSize + 3)

		ecb := engine.ECB(modes.PaddingNone)
		if err := ecb.SetWorkers(1); !errors.Is(err, modes.ErrInvalidInput) {
			t.Fatalf("%s/ECB SetWorkers(1) error=%v", alg.name, err)
		}
		want, err := ecb.Encrypt(nil, aligned)
		if err != nil {
			t.Fatalf("%s/ECB encrypt: %v", alg.name, err)
		}
		if err := ecb.SetWorkers(4); err != nil {
			t.Fatalf("%s/ECB SetWorkers: %v", alg.name, err)
		}
		got, err := ecb.Encrypt(nil, aligned)
		if err != nil {
			t.Fatalf("%s/ECB persistent encrypt: %v", alg.name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s/ECB persistent encrypt mismatch", alg.name)
		}
		plain, err := ecb.Decrypt(nil, want)
		if err != nil {
			t.Fatalf("%s/ECB persistent decrypt: %v", alg.name, err)
		}
		if !bytes.Equal(plain, aligned) {
			t.Fatalf("%s/ECB persistent decrypt mismatch", alg.name)
		}
		ecb.ResetWorkers()
		ecb.Close()
		ecb.Close()
		got, err = ecb.Encrypt(nil, aligned)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s/ECB after close mismatch err=%v", alg.name, err)
		}

		cbc := mustMode(engine.CBC(iv, modes.PaddingNone))
		want, err = cbc.Encrypt(nil, aligned)
		if err != nil {
			t.Fatalf("%s/CBC encrypt: %v", alg.name, err)
		}
		if err := cbc.SetWorkers(4); err != nil {
			t.Fatalf("%s/CBC SetWorkers: %v", alg.name, err)
		}
		got, err = cbc.Decrypt(nil, want)
		if err != nil {
			t.Fatalf("%s/CBC persistent decrypt: %v", alg.name, err)
		}
		if !bytes.Equal(got, aligned) {
			t.Fatalf("%s/CBC persistent decrypt mismatch", alg.name)
		}
		cbc.Close()
		cbc.Close()
		got, err = cbc.Decrypt(nil, want)
		if err != nil || !bytes.Equal(got, aligned) {
			t.Fatalf("%s/CBC after close mismatch err=%v", alg.name, err)
		}

		cfb := mustMode(engine.CFB(iv))
		want, err = cfb.Encrypt(nil, streamPlaintext)
		if err != nil {
			t.Fatalf("%s/CFB encrypt: %v", alg.name, err)
		}
		if err := cfb.SetWorkers(4); err != nil {
			t.Fatalf("%s/CFB SetWorkers: %v", alg.name, err)
		}
		got, err = cfb.Decrypt(nil, want)
		if err != nil {
			t.Fatalf("%s/CFB persistent decrypt: %v", alg.name, err)
		}
		if !bytes.Equal(got, streamPlaintext) {
			t.Fatalf("%s/CFB persistent decrypt mismatch", alg.name)
		}
		cfb.ResetWorkers()
		cfb.Close()
		got, err = cfb.Decrypt(nil, want)
		if err != nil || !bytes.Equal(got, streamPlaintext) {
			t.Fatalf("%s/CFB after close mismatch err=%v", alg.name, err)
		}

		ctr := mustMode(engine.CTR(iv))
		want, err = ctr.XORKeyStream(nil, streamPlaintext)
		if err != nil {
			t.Fatalf("%s/CTR encrypt: %v", alg.name, err)
		}
		if err := ctr.SetWorkers(4); err != nil {
			t.Fatalf("%s/CTR SetWorkers: %v", alg.name, err)
		}
		got, err = ctr.XORKeyStream(nil, streamPlaintext)
		if err != nil {
			t.Fatalf("%s/CTR persistent xor: %v", alg.name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s/CTR persistent xor mismatch", alg.name)
		}
		ctr.Close()
		ctr.Close()
		got, err = ctr.XORKeyStream(nil, streamPlaintext)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s/CTR after close mismatch err=%v", alg.name, err)
		}

		acpkm := mustMode(engine.CTRACPKM(iv, modes.DefaultACPKMSectionSize))
		if err := acpkm.PrecomputeSections(len(streamPlaintext)); err != nil {
			t.Fatalf("%s/CTR-ACPKM precompute: %v", alg.name, err)
		}
		want, err = acpkm.XORKeyStream(nil, streamPlaintext)
		if err != nil {
			t.Fatalf("%s/CTR-ACPKM encrypt: %v", alg.name, err)
		}
		if err := acpkm.SetWorkers(4); err != nil {
			t.Fatalf("%s/CTR-ACPKM SetWorkers: %v", alg.name, err)
		}
		got, err = acpkm.XORKeyStream(nil, streamPlaintext)
		if err != nil {
			t.Fatalf("%s/CTR-ACPKM persistent xor: %v", alg.name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s/CTR-ACPKM persistent xor mismatch", alg.name)
		}
		acpkm.ResetWorkers()
		acpkm.Close()
		got, err = acpkm.XORKeyStream(nil, streamPlaintext)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s/CTR-ACPKM after close mismatch err=%v", alg.name, err)
		}
	}
}

const parallelTestSize = 64 * 1024

func TestFeedbackSegmentAndRegister(t *testing.T) {
	engine, err := modes.NewKuznechik(testKey())
	if err != nil {
		t.Fatal(err)
	}
	iv := testIV(2 * gost3412128.BlockSize)
	plaintext := testPlaintext(77)

	cfb, err := engine.CFBN(iv, 3, 2*gost3412128.BlockSize)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := cfb.Encrypt(nil, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := cfb.Decrypt(nil, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("CFB segment/register round-trip mismatch")
	}

	ofb, err := engine.OFBN(iv, 3, 2*gost3412128.BlockSize)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err = ofb.Encrypt(nil, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err = ofb.Decrypt(nil, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("OFB segment/register round-trip mismatch")
	}
}

func TestMAC(t *testing.T) {
	for _, alg := range []modes.Algorithm{modes.AlgorithmGOST28147, modes.AlgorithmMagma, modes.AlgorithmKuznechik} {
		engine, _ := newTestEngine(t, alg)
		mac, err := engine.MAC(4)
		if err != nil {
			t.Fatal(err)
		}
		plaintext := []byte("authenticated message")
		tag := mac.Sum(nil, plaintext)
		if len(tag) != 4 {
			t.Fatalf("tag length=%d", len(tag))
		}
		if !mac.Verify(plaintext, tag) {
			t.Fatal("valid MAC rejected")
		}
		tag[0] ^= 0xff
		if mac.Verify(plaintext, tag) {
			t.Fatal("tampered MAC accepted")
		}
	}
}

func TestMGMAuthFailure(t *testing.T) {
	engine, err := modes.NewKuznechik(testKey())
	if err != nil {
		t.Fatal(err)
	}
	aead, err := engine.MGM(0)
	if err != nil {
		t.Fatal(err)
	}
	nonce := testIV(gost3412128.BlockSize)
	ciphertext, err := aead.Seal(nil, []byte(nonce), []byte("secret"), []byte("metadata"))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[0] ^= 0xff
	_, err = aead.Open(nil, nonce, ciphertext, []byte("metadata"))
	if !errors.Is(err, modes.ErrAuthFailed) {
		t.Fatalf("decrypt error=%v, want ErrAuthFailed", err)
	}
}

func TestParseStringHelpers(t *testing.T) {
	alg, err := modes.ParseAlgorithm("gost28147")
	if err != nil {
		t.Fatal(err)
	}
	if alg != modes.AlgorithmGOST28147 || alg.String() != "gost28147" {
		t.Fatalf("algorithm=%v string=%q", alg, alg.String())
	}

	alg, err = modes.ParseAlgorithm("GOST-34.12-128")
	if err != nil {
		t.Fatal(err)
	}
	if alg != modes.AlgorithmKuznechik || alg.String() != "kuznechik" {
		t.Fatalf("algorithm=%v string=%q", alg, alg.String())
	}

	alg, err = modes.ParseAlgorithm("magma")
	if err != nil {
		t.Fatal(err)
	}
	if alg != modes.AlgorithmMagma || alg.String() != "magma" {
		t.Fatalf("algorithm=%v string=%q", alg, alg.String())
	}

	mode, err := modes.ParseMode("CTR-ACPKM")
	if err != nil {
		t.Fatal(err)
	}
	if mode != modes.ModeCTRACPKM || mode.String() != "ctr-acpkm" {
		t.Fatalf("mode=%v string=%q", mode, mode.String())
	}

	mode, err = modes.ParseMode("aead")
	if err != nil {
		t.Fatal(err)
	}
	if mode != modes.ModeMGM || mode.String() != "mgm" {
		t.Fatalf("mode=%v string=%q", mode, mode.String())
	}

	if _, err = modes.ParseAlgorithm("unknown"); !errors.Is(err, modes.ErrInvalidAlgorithm) {
		t.Fatalf("algorithm error=%v", err)
	}
	if _, err = modes.ParseMode("unknown"); !errors.Is(err, modes.ErrInvalidMode) {
		t.Fatalf("mode error=%v", err)
	}
}

func TestInvalidInputs(t *testing.T) {
	if _, err := modes.NewKuznechik(testKey()[:31]); !errors.Is(err, modes.ErrInvalidKeySize) {
		t.Fatalf("key error=%v", err)
	}
	engine, err := modes.NewKuznechik(testKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = engine.CTR(testIV(3)); !errors.Is(err, modes.ErrInvalidIVSize) {
		t.Fatalf("iv error=%v", err)
	}
	if _, err = engine.CFBN(testIV(gost3412128.BlockSize), gost3412128.BlockSize+1, gost3412128.BlockSize); !errors.Is(err, modes.ErrInvalidInput) {
		t.Fatalf("feedback error=%v", err)
	}
	_, err = engine.ECB(modes.PaddingNone).Encrypt(nil, []byte("not-aligned"))
	if !errors.Is(err, modes.ErrInvalidInput) {
		t.Fatalf("block alignment error=%v", err)
	}
}

func TestPreparedInPlaceAndAppend(t *testing.T) {
	engine, err := modes.NewKuznechik(testKey())
	if err != nil {
		t.Fatal(err)
	}
	iv := testIV(gost3412128.BlockSize)
	plaintext := testPlaintext(41)

	streams := []struct {
		name string
		mode interface {
			Encrypt([]byte, []byte) ([]byte, error)
			Decrypt([]byte, []byte) ([]byte, error)
		}
	}{
		{"CFB", mustMode(engine.CFB(iv))},
		{"OFB", mustMode(engine.OFB(iv))},
		{"CTR", mustMode(engine.CTR(iv))},
		{"CTR-ACPKM", mustMode(engine.CTRACPKM(iv, modes.DefaultACPKMSectionSize))},
	}
	for _, tc := range streams {
		buf := append([]byte(nil), plaintext...)
		ciphertext, err := tc.mode.Encrypt(buf[:0], buf)
		if err != nil {
			t.Fatalf("%s encrypt: %v", tc.name, err)
		}
		decrypted, err := tc.mode.Decrypt(ciphertext[:0], ciphertext)
		if err != nil {
			t.Fatalf("%s decrypt: %v", tc.name, err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("%s in-place round-trip mismatch", tc.name)
		}

		dst := make([]byte, 7, 7+len(plaintext))
		out, err := tc.mode.Encrypt(dst, plaintext)
		if err != nil {
			t.Fatalf("%s append: %v", tc.name, err)
		}
		if len(out) != 7+len(plaintext) {
			t.Fatalf("%s append length=%d", tc.name, len(out))
		}
	}

	block := mustMode(engine.CBC(iv, modes.PaddingDefault))
	ciphertext, err := block.Encrypt(nil, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	buf := append([]byte(nil), ciphertext...)
	decrypted, err := block.Decrypt(buf[:0], buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("CBC in-place decrypt mismatch")
	}
}

func TestPartialOverlapRejected(t *testing.T) {
	engine, err := modes.NewKuznechik(testKey())
	if err != nil {
		t.Fatal(err)
	}
	cfb, err := engine.CFB(testIV(gost3412128.BlockSize))
	if err != nil {
		t.Fatal(err)
	}
	buf := testPlaintext(64)
	_, err = cfb.Encrypt(buf[1:1], buf[:32])
	if !errors.Is(err, modes.ErrInvalidOverlap) {
		t.Fatalf("overlap error=%v", err)
	}
}

func mustMode[T any](mode T, err error) T {
	if err != nil {
		panic(err)
	}
	return mode
}

func isStreamMode(mode modes.Mode) bool {
	switch mode {
	case modes.ModeCFB, modes.ModeOFB, modes.ModeCTR, modes.ModeCTRACPKM:
		return true
	default:
		return false
	}
}
