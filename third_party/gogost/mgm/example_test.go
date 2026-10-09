package mgm_test

import (
	"bytes"
	"fmt"

	"gitverse.ru/uzer_007/gogost/v3/gost3412128"
	"gitverse.ru/uzer_007/gogost/v3/mgm"
)

func Example() {
	key := []byte("0123456789abcdef0123456789abcdef")
	nonce := []byte("1234567890abcdef")
	plaintext := []byte("message")
	additionalData := []byte("metadata")

	aead, err := mgm.NewMGM(gost3412128.NewCipher(key), gost3412128.BlockSize)
	if err != nil {
		panic(err)
	}

	sealed := aead.Seal(nil, nonce, plaintext, additionalData)
	opened, err := aead.Open(nil, nonce, sealed, additionalData)
	if err != nil {
		panic(err)
	}

	fmt.Println(bytes.Equal(opened, plaintext), aead.Overhead())
	// Output: true 16
}
