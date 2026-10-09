package yescrypt

import (
	"bytes"
	"strconv"
	"testing"

	upstream "github.com/go-crypt/x/yescrypt"
)

func TestKeyMatchesUpstream(t *testing.T) {
	tests := []struct {
		name     string
		password []byte
		salt     []byte
	}{
		{name: "empty", password: nil, salt: nil},
		{name: "ascii", password: []byte("password"), salt: []byte("salt")},
		{name: "utf8", password: []byte("Пароль-совместимость-2026"), salt: []byte("pass1234salt45678")},
		{name: "binary", password: bytes.Repeat([]byte{0, 1, 0xff, 0x80}, 19), salt: bytes.Repeat([]byte{0xff, 0}, 23)},
	}

	for _, tt := range tests {
		for _, keyLen := range []int{32, 64} {
			t.Run(tt.name+"/"+strconv.Itoa(keyLen), func(t *testing.T) {
				got, err := Key(tt.password, tt.salt, keyLen)
				if err != nil {
					t.Fatal(err)
				}
				want, err := upstream.Key(tt.password, tt.salt, N, r, 1, keyLen)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("Key() = %x, want %x", got, want)
				}
			})
		}
	}
}

func BenchmarkKey(b *testing.B) {
	password := []byte("benchmark-password-123456")
	salt := []byte("benchmark-salt-123456")
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Key(password, salt, 32); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKeyUpstream(b *testing.B) {
	password := []byte("benchmark-password-123456")
	salt := []byte("benchmark-salt-123456")
	b.ReportAllocs()
	for b.Loop() {
		if _, err := upstream.Key(password, salt, N, r, 1, 32); err != nil {
			b.Fatal(err)
		}
	}
}
