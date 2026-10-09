// Package gost34112012256 реализует 256-битный Стрибог
// (ГОСТ Р 34.11-2012, RFC 6986), KDF, TLS tree, ESP tree и вспомогательные функции GOST yescrypt.
package gost34112012256

import (
	"hash"

	"gitverse.ru/uzer_007/gogost/v3/internal/gost34112012"
)

const (
	BlockSize = gost34112012.BlockSize
	Size      = 32
)

/*
func init() {
	crypto.RegisterHash(crypto.GOSTR34112012256, New)
}
*/

func New() hash.Hash {
	return gost34112012.New(32)
}

func Sum(data []byte) [Size]byte {
	return gost34112012.Sum256(data)
}

func GostYescrypt(salt []byte, password []byte) ([]byte, error) {
	if salt == nil {
		salt = []byte("salt45678salt45678")
	}
	return gost34112012.GostYescrypt(256, salt, password)
}

func FormatGostYescryptHash(salt []byte, hash512 []byte) string {
	if salt == nil {
		salt = []byte("salt45678salt45678")
	}
	return gost34112012.FormatGostYescryptHash(256, salt, hash512)
}

// VerifyGostYescryptHash проверяет пароль по строке, созданной FormatGostYescryptHash.
func VerifyGostYescryptHash(encoded string, password []byte) (bool, error) {
	return gost34112012.VerifyGostYescryptHash(256, encoded, password)
}
