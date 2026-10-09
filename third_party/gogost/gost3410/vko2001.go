package gost3410

import (
	"errors"
	"math/big"

	"gitverse.ru/uzer_007/gogost/v3/gost28147"
	"gitverse.ru/uzer_007/gogost/v3/gost341194"
	"gitverse.ru/uzer_007/gogost/v3/internal/errx"
)

// KEK2001 вырабатывает общий ключ VKO ГОСТ Р 34.10-2001 по RFC 4357.
// ukm задаёт пользовательский ключевой материал, также называемый фактором VKO.
func (prv *PrivateKey) KEK2001(pub *PublicKey, ukm *big.Int) ([]byte, error) {
	if prv.C.PointSize() != 32 {
		return nil, errors.New("gogost/gost3410: KEK2001 доступен только для 256-битных кривых")
	}
	key, err := prv.KEK(pub, ukm)
	if err != nil {
		return nil, errx.PrefixText("gogost/gost3410.PrivateKey.KEK2001", err)
	}
	h := gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
	if _, err = h.Write(key); err != nil {
		return nil, errx.PrefixText("gogost/gost3410.PrivateKey.KEK2001", err)
	}
	return h.Sum(key[:0]), nil
}
