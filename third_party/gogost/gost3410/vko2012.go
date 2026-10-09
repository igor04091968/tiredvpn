package gost3410

import (
	"math/big"

	"gitverse.ru/uzer_007/gogost/v3/gost34112012256"
	"gitverse.ru/uzer_007/gogost/v3/gost34112012512"
	"gitverse.ru/uzer_007/gogost/v3/internal/errx"
)

// KEK2012256 вырабатывает общий ключ VKO ГОСТ Р 34.10-2012 по RFC 7836
// со Стрибог-256. ukm задаёт пользовательский ключевой материал, также
// называемый фактором VKO.
func (prv *PrivateKey) KEK2012256(pub *PublicKey, ukm *big.Int) ([]byte, error) {
	key, err := prv.KEK(pub, ukm)
	if err != nil {
		return nil, errx.PrefixText("gogost/gost3410.PrivateKey.KEK2012256", err)
	}
	h := gost34112012256.New()
	if _, err = h.Write(key); err != nil {
		return nil, errx.PrefixText("gogost/gost3410.PrivateKey.KEK2012256", err)
	}
	return h.Sum(key[:0]), nil
}

// KEK2012512 вырабатывает общий ключ VKO ГОСТ Р 34.10-2012 по RFC 7836
// со Стрибог-512. ukm задаёт пользовательский ключевой материал, также
// называемый фактором VKO.
func (prv *PrivateKey) KEK2012512(pub *PublicKey, ukm *big.Int) ([]byte, error) {
	key, err := prv.KEK(pub, ukm)
	if err != nil {
		return nil, errx.PrefixText("gogost/gost3410.PrivateKey.KEK2012512", err)
	}
	h := gost34112012512.New()
	if _, err = h.Write(key); err != nil {
		return nil, errx.PrefixText("gogost/gost3410.PrivateKey.KEK2012512", err)
	}
	return h.Sum(key[:0]), nil
}
