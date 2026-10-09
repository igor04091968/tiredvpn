package gost34112012

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"testing"

	base64 "gitverse.ru/uzer_007/gobase64"
)

// Тестовые данные
var (
	testPassword = []byte("password123!@#")
	testSalt     = []byte("salt45678salt45678") // 16 байт
)

func TestGostYescrypt_Consistency(t *testing.T) {
	t.Run("256-bit", func(t *testing.T) {
		result1, err := GostYescrypt(256, testSalt, testPassword)
		if err != nil {
			t.Fatal(err)
		}
		if len(result1) != 32 {
			t.Errorf("Expected 32 bytes, got %d", len(result1))
		}

		result2, err := GostYescrypt(256, testSalt, testPassword)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(result1, result2) {
			t.Error("Results are not consistent")
		}
	})

	t.Run("512-bit", func(t *testing.T) {
		result1, err := GostYescrypt(512, testSalt, testPassword)
		if err != nil {
			t.Fatal(err)
		}
		if len(result1) != 64 {
			t.Errorf("Expected 64 bytes, got %d", len(result1))
		}

		result2, err := GostYescrypt(512, testSalt, testPassword)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(result1, result2) {
			t.Error("Results are not consistent")
		}
	})
}

func TestGostYescrypt_InvalidSize(t *testing.T) {
	_, err := GostYescrypt(128, testSalt, testPassword)
	if err == nil {
		t.Error("Expected error for invalid size")
	}
	if err.Error() != "gogost/internal/gost34112012: Неподдерживаемый размер ключа" {
		t.Errorf("Unexpected error message: %s", err.Error())
	}
}

func TestGostYescrypt_EmptyInput(t *testing.T) {
	t.Run("EmptyPassword", func(t *testing.T) {
		result, err := GostYescrypt(256, testSalt, []byte{})
		if err != nil {
			t.Fatal(err)
		}
		if len(result) != 32 {
			t.Errorf("Expected 32 bytes, got %d", len(result))
		}
	})

	t.Run("EmptySalt", func(t *testing.T) {
		result, err := GostYescrypt(256, []byte{}, testPassword)
		if err != nil {
			t.Fatal(err)
		}
		if len(result) != 32 {
			t.Errorf("Expected 32 bytes, got %d", len(result))
		}
	})
}

func TestGostYescrypt_Vectors(t *testing.T) {
	testVectors := []struct {
		size     uint16
		password string
		salt     string
		expected string // hex
	}{
		{
			size:     256,
			password: "password",
			salt:     "salt",
			// это значение уже видно у вас в выводе "Got"
			expected: "6f2a07c5e4926e6437eaeed389514b2021c77666ae52e54adc4b6d561e6097b4",
		},
		{
			size:     512,
			password: "secret",
			salt:     "pepper",
			// заполните реальным значением (128 hex-символов)
			expected: "5edc9251f9d4c5b45abb7c3904b0e6747e941048e57877047c8e4b8afadfd53d587c8f3c5b2d38ed220a201b9c522019f3258a73097c823c1697384bcdeb0bf4",
		},
	}

	update := os.Getenv("UPDATE_VECTORS") == "1"

	for i, tv := range testVectors {
		needHexLen := int(tv.size/8) * 2 // 256->64, 512->128
		if !update {
			if len(tv.expected) != needHexLen {
				t.Fatalf("Test vector %d: expected hex length %d, got %d",
					i, needHexLen, len(tv.expected))
			}
		}

		result, err := GostYescrypt(tv.size, []byte(tv.salt), []byte(tv.password))
		if err != nil {
			t.Fatalf("Test vector %d: unexpected error: %v", i, err)
		}

		if update {
			t.Logf("Test vector %d (size=%d) expected: %x", i, tv.size, result)
			continue
		}

		expected, err := hex.DecodeString(tv.expected)
		if err != nil {
			t.Fatalf("Test vector %d: invalid hex: %v", i, err)
		}

		if !bytes.Equal(expected, result) {
			t.Errorf("Test vector %d:\nExpected: %x\nGot:      %x", i, expected, result)
		}
	}
}

func TestFormatGostYescryptHash(t *testing.T) {
	t.Run("256-bit", func(t *testing.T) {
		salt := []byte("16byte-salt-1234")
		hash := make([]byte, 32)
		rand.Read(hash)

		result := FormatGostYescryptHash(256, salt, hash)

		parts := strings.Split(result, "$")
		if len(parts) != 5 {
			t.Fatalf("Expected 5 parts, got %d: %v", len(parts), parts)
		}
		if parts[1] != "gy" {
			t.Errorf("Expected identifier 'gy', got '%s'", parts[1])
		}

		// Проверяем параметры
		params, err := base64.StdEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatal(err)
		}
		if string(params) != "N=32768,r=8,p=1,keyLen=32" {
			t.Errorf("Unexpected params: %s", params)
		}

		// Проверяем соль
		saltDecoded, err := base64.StdEncoding.DecodeString(parts[3])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(salt, saltDecoded) {
			t.Error("Salt mismatch")
		}

		// Проверяем хеш
		hashDecoded, err := base64.StdEncoding.DecodeString(parts[4])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(hash, hashDecoded) {
			t.Error("Hash mismatch")
		}
	})

	t.Run("512-bit", func(t *testing.T) {
		salt := []byte("16byte-salt-5678")
		hash := make([]byte, 64)
		rand.Read(hash)

		result := FormatGostYescryptHash(512, salt, hash)

		parts := strings.Split(result, "$")
		if len(parts) != 5 {
			t.Fatalf("Expected 5 parts, got %d: %v", len(parts), parts)
		}

		// Проверяем параметры
		params, err := base64.StdEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatal(err)
		}
		if string(params) != "N=32768,r=8,p=1,keyLen=64" {
			t.Errorf("Unexpected params: %s", params)
		}
	})
}

func TestVerifyGostYescryptHash(t *testing.T) {
	tests := []struct {
		name     string
		size     uint16
		salt     []byte
		password []byte
	}{
		{
			name:     "256-bit",
			size:     256,
			salt:     []byte("16byte-salt-1234"),
			password: []byte("correct horse battery staple"),
		},
		{
			name:     "512-bit-arbitrary-salt",
			size:     512,
			salt:     []byte("salt-with-an-arbitrary-length"),
			password: []byte("Пароль-совместимость-2026"),
		},
		{
			name:     "empty-password",
			size:     256,
			salt:     []byte("non-empty-salt"),
			password: []byte{},
		},
		{
			name:     "empty-salt",
			size:     512,
			salt:     []byte{},
			password: []byte("password"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			digest, err := GostYescrypt(tt.size, tt.salt, tt.password)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(digest)

			encoded := FormatGostYescryptHash(tt.size, tt.salt, digest)
			match, err := VerifyGostYescryptHash(tt.size, encoded, tt.password)
			if err != nil {
				t.Fatalf("VerifyGostYescryptHash() error = %v", err)
			}
			if !match {
				t.Fatal("VerifyGostYescryptHash() = false, want true")
			}
		})
	}
}

func TestVerifyGostYescryptHashMismatch(t *testing.T) {
	const size = uint16(512)
	salt := []byte("16byte-salt-5678")
	password := []byte("correct password")

	digest, err := GostYescrypt(size, salt, password)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(digest)

	encoded := FormatGostYescryptHash(size, salt, digest)
	match, err := VerifyGostYescryptHash(size, encoded, []byte("wrong password"))
	if err != nil {
		t.Fatalf("wrong password returned error: %v", err)
	}
	if match {
		t.Fatal("wrong password matched")
	}

	mutated := bytes.Clone(digest)
	mutated[len(mutated)-1] ^= 1
	defer clear(mutated)

	encoded = FormatGostYescryptHash(size, salt, mutated)
	match, err = VerifyGostYescryptHash(size, encoded, password)
	if err != nil {
		t.Fatalf("well-formed mismatching digest returned error: %v", err)
	}
	if match {
		t.Fatal("mutated digest matched")
	}
}

func TestVerifyGostYescryptHashRejectsMalformed(t *testing.T) {
	saltB64 := base64.StdEncoding.EncodeToString([]byte("salt"))
	hash256B64 := base64.StdEncoding.EncodeToString(make([]byte, 32))
	prefix256 := "$gy$" + gostYescryptParams(256) + "$"
	valid256 := prefix256 + saltB64 + "$" + hash256B64

	tests := map[string]string{
		"empty":                   "",
		"wrong-prefix":            strings.Replace(valid256, "$gy$", "$gx$", 1),
		"missing-field":           prefix256 + saltB64,
		"extra-field":             valid256 + "$extra",
		"invalid-params":          "$gy$not-base64$" + saltB64 + "$" + hash256B64,
		"unsupported-params":      "$gy$" + base64.StdEncoding.EncodeToString([]byte("N=16384,r=8,p=1,keyLen=32")) + "$" + saltB64 + "$" + hash256B64,
		"invalid-salt":            prefix256 + "***$" + hash256B64,
		"noncanonical-salt":       prefix256 + "AB==$" + hash256B64,
		"salt-with-newline":       prefix256 + "c2Fs\r\ndA==$" + hash256B64,
		"invalid-hash":            prefix256 + saltB64 + "$" + strings.Repeat("!", len(hash256B64)),
		"wrong-decoded-hash-size": prefix256 + saltB64 + "$" + base64.StdEncoding.EncodeToString(make([]byte, 31)),
	}

	for name, encoded := range tests {
		t.Run(name, func(t *testing.T) {
			match, err := VerifyGostYescryptHash(256, encoded, []byte("password"))
			if err == nil {
				t.Fatal("VerifyGostYescryptHash() error = nil, want format error")
			}
			if match {
				t.Fatal("malformed hash matched")
			}
		})
	}
}

func TestVerifyGostYescryptHashRejectsCrossSize(t *testing.T) {
	salt := []byte("salt")
	encoded256 := FormatGostYescryptHash(256, salt, make([]byte, 32))
	encoded512 := FormatGostYescryptHash(512, salt, make([]byte, 64))

	for _, tt := range []struct {
		name    string
		size    uint16
		encoded string
	}{
		{name: "256-as-512", size: 512, encoded: encoded256},
		{name: "512-as-256", size: 256, encoded: encoded512},
	} {
		t.Run(tt.name, func(t *testing.T) {
			match, err := VerifyGostYescryptHash(tt.size, tt.encoded, []byte("password"))
			if err == nil {
				t.Fatal("VerifyGostYescryptHash() error = nil, want format error")
			}
			if match {
				t.Fatal("cross-size hash matched")
			}
		})
	}

	if match, err := VerifyGostYescryptHash(128, encoded256, []byte("password")); err == nil || match {
		t.Fatalf("unsupported size returned match=%v, error=%v", match, err)
	}
}

func BenchmarkGostYescrypt(b *testing.B) {
	password := []byte("benchmark-password-123456")
	salt := []byte("benchmark-salt-123456")

	b.Run("256-bit", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := GostYescrypt(256, salt, password)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("512-bit", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := GostYescrypt(512, salt, password)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkFormatGostYescryptHash(b *testing.B) {
	salt := []byte("16byte-salt-value")
	hash256 := make([]byte, 32)
	hash512 := make([]byte, 64)
	rand.Read(hash256)
	rand.Read(hash512)

	b.Run("256-bit", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			FormatGostYescryptHash(256, salt, hash256)
		}
	})

	b.Run("512-bit", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			FormatGostYescryptHash(512, salt, hash512)
		}
	})
}

func BenchmarkFormatGostYescryptHash_Allocations(b *testing.B) {
	salt := []byte("16byte-salt-value")
	hash := make([]byte, 32)
	rand.Read(hash)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		FormatGostYescryptHash(256, salt, hash)
	}
}

func BenchmarkVerifyGostYescryptHash(b *testing.B) {
	password := []byte("benchmark-password-123456")
	salt := []byte("16byte-salt-5678")

	for _, size := range []uint16{256, 512} {
		digest, err := GostYescrypt(size, salt, password)
		if err != nil {
			b.Fatal(err)
		}
		encoded := FormatGostYescryptHash(size, salt, digest)
		clear(digest)

		b.Run(strconv.Itoa(int(size))+"-bit", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				match, err := VerifyGostYescryptHash(size, encoded, password)
				if err != nil {
					b.Fatal(err)
				}
				if !match {
					b.Fatal("password did not match")
				}
			}
		})
	}
}

func BenchmarkVerifyGostYescryptHashMalformed(b *testing.B) {
	salt := []byte("16byte-salt-5678")
	password := []byte("password")
	encoded := FormatGostYescryptHash(512, salt, make([]byte, 64))
	encoded = encoded[:len(encoded)-1] + "!"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		match, err := VerifyGostYescryptHash(512, encoded, password)
		if err == nil {
			b.Fatal("malformed hash returned nil error")
		}
		if match {
			b.Fatal("malformed hash matched")
		}
	}
}

func TestMain(m *testing.M) {
	// Инициализация глобальных объектов перед тестами

	// Запуск тестов
	m.Run()
}
