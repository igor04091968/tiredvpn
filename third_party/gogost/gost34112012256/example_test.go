package gost34112012256_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"strings"

	"gitverse.ru/uzer_007/gogost/v3/gost34112012256"
)

func Example() {
	h := gost34112012256.New()
	_, _ = h.Write([]byte("gogost"))
	sum := h.Sum(nil)

	yescryptHash, err := gost34112012256.GostYescrypt(
		[]byte("1234567890abcdef"),
		[]byte("password"),
	)
	if err != nil {
		panic(err)
	}
	formatted := gost34112012256.FormatGostYescryptHash(
		[]byte("1234567890abcdef"),
		yescryptHash,
	)

	fmt.Println(len(sum), len(yescryptHash), strings.HasPrefix(formatted, "$gy$"))
	// Output: 32 32 true
}

func ExampleGostYescrypt_passwordHash() {
	password := []byte("correct horse battery staple")
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}

	hash, err := gost34112012256.GostYescrypt(salt, password)
	if err != nil {
		panic(err)
	}
	record := gost34112012256.FormatGostYescryptHash(salt, hash)

	ok, err := gost34112012256.VerifyGostYescryptHash(record, password)
	if err != nil {
		panic(err)
	}

	fmt.Println(strings.HasPrefix(record, "$gy$"), ok)
	// Output: true true
}

func ExampleKDF_DeriveInto() {
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		panic(err)
	}

	kdf := gost34112012256.NewKDF(master)
	encryptionKey := kdf.DeriveInto(nil, []byte("encryption"), []byte("file:42"))
	macKey := kdf.DeriveInto(nil, []byte("mac"), []byte("file:42"))

	fmt.Println(len(encryptionKey), len(macKey), bytes.Equal(encryptionKey, macKey))
	// Output: 32 32 false
}
