package gost28147_test

import (
	"crypto/cipher"
	"fmt"

	"gitverse.ru/uzer_007/gogost/v3/gost28147"
)

func Example() {
	key := make([]byte, gost28147.KeySize)
	block := gost28147.NewCipher(key, gost28147.SboxDefault)
	var _ cipher.Block = block

	dst := make([]byte, gost28147.BlockSize)
	block.Encrypt(dst, make([]byte, gost28147.BlockSize))

	fmt.Println(block.BlockSize(), len(dst))
	// Output: 8 8
}
