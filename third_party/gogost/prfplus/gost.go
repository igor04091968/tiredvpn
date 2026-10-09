// Package prfplus реализует PRF+ для IPsec/IKE на базе
// ГОСТ Р 34.11-2012-256/512 по Р 50.1.113-2016.
package prfplus

import (
	"crypto/hmac"
	"hash"

	"gitverse.ru/uzer_007/gogost/v3/gost34112012256"
	"gitverse.ru/uzer_007/gogost/v3/gost34112012512"
)

type PRFIPsecPRFPlusGOSTR34112012 struct{ h hash.Hash }

func NewPRFIPsecPRFPlusGOSTR34112012256(key []byte) PRFForPlus {
	return PRFIPsecPRFPlusGOSTR34112012{hmac.New(gost34112012256.New, key)}
}

func NewPRFIPsecPRFPlusGOSTR34112012512(key []byte) PRFForPlus {
	return PRFIPsecPRFPlusGOSTR34112012{hmac.New(gost34112012512.New, key)}
}

func (prf PRFIPsecPRFPlusGOSTR34112012) BlockSize() int {
	return prf.h.Size()
}

func (prf PRFIPsecPRFPlusGOSTR34112012) Derive(salt []byte) []byte {
	if _, err := prf.h.Write(salt); err != nil {
		panic(err)
	}
	sum := prf.h.Sum(nil)
	prf.h.Reset()
	return sum
}

func (prf PRFIPsecPRFPlusGOSTR34112012) DeriveTo(dst, salt []byte) []byte {
	if _, err := prf.h.Write(salt); err != nil {
		panic(err)
	}
	sum := prf.h.Sum(dst)
	prf.h.Reset()
	return sum
}
