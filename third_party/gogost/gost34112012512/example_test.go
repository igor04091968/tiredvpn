package gost34112012512_test

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"fmt"

	"gitverse.ru/uzer_007/gogost/v3/gost34112012512"
)

func Example() {
	h := gost34112012512.New()
	_, _ = h.Write([]byte("gogost"))
	sum := h.Sum(nil)

	fmt.Println(len(sum))
	// Output: 64
}

func ExampleNew_pbkdf2() {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}

	key, err := pbkdf2.Key(
		gost34112012512.New,
		"password phrase",
		salt,
		200_000,
		32,
	)
	if err != nil {
		panic(err)
	}

	fmt.Println(len(key))
	// Output: 32
}
