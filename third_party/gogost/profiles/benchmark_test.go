package profiles_test

import (
	"testing"

	"gitverse.ru/uzer_007/gogost/v3/gost3412128"
	"gitverse.ru/uzer_007/gogost/v3/profiles"
)

var (
	benchProfileBytes []byte
	benchProfileErr   error
)

func benchProfileKey() []byte {
	key := make([]byte, gost3412128.KeySize)
	for i := range key {
		key[i] = byte(i*13 + 5)
	}
	return key
}

func benchProfileData(n int) []byte {
	data := make([]byte, n)
	for i := range data {
		data[i] = byte(i*29 + 7)
	}
	return data
}

func BenchmarkProfiles(b *testing.B) {
	key := benchProfileKey()
	iv := benchProfileData(gost3412128.BlockSize)
	ctrIV := iv[:gost3412128.BlockSize/2]
	ad := []byte("metadata")
	for _, size := range []struct {
		name string
		n    int
	}{
		{"16B", 16},
		{"64B", 64},
		{"1KiB", 1024},
		{"16KiB", 16 * 1024},
		{"1MiB", 1024 * 1024},
	} {
		plaintext := benchProfileData(size.n)
		b.Run("CTR-ACPKM/Create/"+size.name, func(b *testing.B) {
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				stream, err := profiles.FileEncryptionKuznechikCTRACPKM(key, ctrIV)
				if err != nil {
					b.Fatal(err)
				}
				benchProfileBytes, benchProfileErr = stream.Encrypt(make([]byte, 0, len(plaintext)), plaintext)
				if benchProfileErr != nil {
					b.Fatal(benchProfileErr)
				}
			}
		})
		b.Run("CTR-ACPKM/Reuse/"+size.name, func(b *testing.B) {
			stream, err := profiles.FileEncryptionKuznechikCTRACPKM(key, ctrIV)
			if err != nil {
				b.Fatal(err)
			}
			if _, err = stream.Encrypt(make([]byte, 0, len(plaintext)), plaintext); err != nil {
				b.Fatal(err)
			}
			dst := make([]byte, 0, len(plaintext))
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchProfileBytes, benchProfileErr = stream.Encrypt(dst[:0], plaintext)
				if benchProfileErr != nil {
					b.Fatal(benchProfileErr)
				}
			}
		})
		b.Run("MGM/Create/"+size.name, func(b *testing.B) {
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				aead, err := profiles.MessageEncryptionMGM(key)
				if err != nil {
					b.Fatal(err)
				}
				benchProfileBytes, benchProfileErr = aead.Seal(make([]byte, 0, len(plaintext)+gost3412128.BlockSize), iv, plaintext, ad)
				if benchProfileErr != nil {
					b.Fatal(benchProfileErr)
				}
			}
		})
		b.Run("MGM/Reuse/"+size.name, func(b *testing.B) {
			aead, err := profiles.MessageEncryptionMGM(key)
			if err != nil {
				b.Fatal(err)
			}
			dst := make([]byte, 0, len(plaintext)+gost3412128.BlockSize)
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchProfileBytes, benchProfileErr = aead.Seal(dst[:0], iv, plaintext, ad)
				if benchProfileErr != nil {
					b.Fatal(benchProfileErr)
				}
			}
		})
	}
}
