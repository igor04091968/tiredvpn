package modes_test

import (
	"bytes"
	"fmt"

	"gitverse.ru/uzer_007/gogost/v3/gost3412128"
	"gitverse.ru/uzer_007/gogost/v3/gost3413/modes"
)

func ExampleKuznechik_CBC() {
	key := []byte("0123456789abcdef0123456789abcdef")
	iv := []byte("1234567890abcdef")
	plaintext := []byte("message")

	engine := modes.MustKuznechik(key)
	cbc, err := engine.CBC(iv, modes.PaddingDefault)
	if err != nil {
		panic(err)
	}
	ciphertext, err := cbc.Encrypt(nil, plaintext)
	if err != nil {
		panic(err)
	}
	decrypted, err := cbc.Decrypt(nil, ciphertext)
	if err != nil {
		panic(err)
	}

	fmt.Println(bytes.Equal(decrypted, plaintext))
	// Output: true
}

func ExampleKuznechik_CTRACPKM() {
	key := []byte("0123456789abcdef0123456789abcdef")
	iv := []byte("12345678")
	plaintext := []byte("message")

	engine := modes.MustKuznechik(key)
	ctr, err := engine.CTRACPKM(iv, modes.DefaultACPKMSectionSize)
	if err != nil {
		panic(err)
	}
	ciphertext, err := ctr.Encrypt(nil, plaintext)
	if err != nil {
		panic(err)
	}
	decrypted, err := ctr.Decrypt(nil, ciphertext)
	if err != nil {
		panic(err)
	}

	fmt.Println(bytes.Equal(decrypted, plaintext))
	// Output: true
}

func ExampleKuznechik_MGM() {
	key := []byte("0123456789abcdef0123456789abcdef")
	nonce := []byte("1234567890abcdef")
	plaintext := []byte("message")

	engine := modes.MustKuznechik(key)
	aead, err := engine.MGM(gost3412128.BlockSize)
	if err != nil {
		panic(err)
	}
	sealed, err := aead.Seal(nil, nonce, plaintext, []byte("metadata"))
	if err != nil {
		panic(err)
	}
	opened, err := aead.Open(nil, nonce, sealed, []byte("metadata"))
	if err != nil {
		panic(err)
	}

	fmt.Println(bytes.Equal(opened, plaintext), len(sealed)-len(plaintext))
	// Output: true 16
}

func ExampleMAC() {
	key := []byte("0123456789abcdef0123456789abcdef")
	data := []byte("message")

	engine := modes.MustKuznechik(key)
	mac, err := engine.MAC(gost3412128.BlockSize)
	if err != nil {
		panic(err)
	}
	tag := mac.Sum(nil, data)

	fmt.Println(mac.Verify(data, tag))
	// Output: true
}
