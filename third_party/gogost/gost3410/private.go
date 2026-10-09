package gost3410

import (
	"crypto"
	"errors"
	"io"
	"math/big"

	"gitverse.ru/uzer_007/gogost/v3/internal/errx"
)

// PrivateKey представляет закрытый ключ ГОСТ Р 34.10, привязанный к кривой.
type PrivateKey struct {
	C   *Curve
	Key *big.Int
}

// NewPrivateKeyLE разбирает little-endian закрытый ключ длиной c.PointSize() байт.
// Скаляр должен быть каноническим: 1 <= d < Q.
func NewPrivateKeyLE(c *Curve, raw []byte) (*PrivateKey, error) {
	if c == nil || c.Q == nil || c.Q.Sign() <= 0 || c.P == nil {
		return nil, errors.New("gogost/gost3410: Некорректная кривая")
	}
	pointSize := c.PointSize()
	if len(raw) != pointSize {
		return nil, errors.New("gogost/gost3410: длина ключа " + errx.Int(len(raw)) + ", ожидалось " + errx.Int(pointSize))
	}
	key := make([]byte, pointSize)
	for i := range len(key) {
		key[i] = raw[len(raw)-i-1]
	}
	k := bytes2big(key)
	if k.Sign() <= 0 || k.Cmp(c.Q) >= 0 {
		return nil, errors.New("gogost/gost3410: Закрытый ключ вне диапазона")
	}
	return &PrivateKey{c, k}, nil
}

// NewPrivateKeyBE разбирает big-endian закрытый ключ длиной c.PointSize() байт.
// Скаляр должен быть каноническим: 1 <= d < Q.
func NewPrivateKeyBE(c *Curve, raw []byte) (*PrivateKey, error) {
	if c == nil || c.Q == nil || c.Q.Sign() <= 0 || c.P == nil {
		return nil, errors.New("gogost/gost3410: Некорректная кривая")
	}
	pointSize := c.PointSize()
	if len(raw) != pointSize {
		return nil, errors.New("gogost/gost3410: длина ключа " + errx.Int(len(raw)) + ", ожидалось " + errx.Int(pointSize))
	}
	k := bytes2big(raw)
	if k.Sign() <= 0 || k.Cmp(c.Q) >= 0 {
		return nil, errors.New("gogost/gost3410: Закрытый ключ вне диапазона")
	}
	return &PrivateKey{c, k}, nil
}

// NewPrivateKey является псевдонимом NewPrivateKeyLE.
func NewPrivateKey(c *Curve, raw []byte) (*PrivateKey, error) {
	return NewPrivateKeyLE(c, raw)
}

// GenPrivateKey генерирует равномерно распределённый допустимый скаляр,
// читая случайные байты из rand и отбрасывая значения вне диапазона.
func GenPrivateKey(c *Curve, rand io.Reader) (*PrivateKey, error) {
	if c == nil || c.Q == nil || c.Q.Cmp(bigInt1) <= 0 || c.P == nil || rand == nil {
		return nil, errors.New("gogost/gost3410: Некорректные параметры генерации ключа")
	}
	bits := c.Q.BitLen()
	if bits > c.PointSize()*8 {
		return nil, errors.New("gogost/gost3410: Некорректный порядок кривой")
	}
	raw := make([]byte, (bits+7)/8)
	defer clear(raw)
	for range 128 {
		if _, err := io.ReadFull(rand, raw); err != nil {
			return nil, errx.PrefixText("gogost/gost3410.GenPrivateKey", err)
		}
		raw[0] &= byte(0xff >> uint(len(raw)*8-bits))
		k := new(big.Int).SetBytes(raw)
		if k.Sign() > 0 && k.Cmp(c.Q) < 0 {
			return &PrivateKey{c, k}, nil
		}
	}
	return nil, errors.New("gogost/gost3410: Не удалось сгенерировать ключ в допустимом диапазоне")
}

// RawLE возвращает закрытый ключ как little-endian байтовую строку.
func (prv *PrivateKey) RawLE() (raw []byte) {
	raw = pad(prv.Key.Bytes(), prv.C.PointSize())
	reverse(raw)
	return raw
}

// RawBE возвращает закрытый ключ как big-endian байтовую строку.
func (prv *PrivateKey) RawBE() (raw []byte) {
	return pad(prv.Key.Bytes(), prv.C.PointSize())
}

// Raw является псевдонимом RawLE.
func (prv *PrivateKey) Raw() []byte {
	return prv.RawLE()
}

// PublicKey вычисляет открытый ключ из закрытого ключа.
func (prv *PrivateKey) PublicKey() (*PublicKey, error) {
	x, y, err := prv.C.expBase(prv.Key)
	if err != nil {
		return nil, errx.PrefixText("gogost/gost3410.PrivateKey.PublicKey", err)
	}
	return &PublicKey{prv.C, x, y}, nil
}

// SignDigest подписывает дайджест и возвращает S||R в little-endian порядке ГОСТ.
func (prv *PrivateKey) SignDigest(digest []byte, rand io.Reader) ([]byte, error) {
	if signature, err, used := prv.C.fixedState.signDigest(prv.C, prv.Key, digest, rand); used {
		if err != nil {
			return nil, errx.PrefixText("gogost/gost3410.PrivateKey.SignDigest", err)
		}
		return signature, nil
	}
	e := bytes2big(digest)
	e.Mod(e, prv.C.Q)
	if e.Cmp(zero) == 0 {
		e.SetInt64(1)
	}
	kRaw := make([]byte, prv.C.PointSize())
	var err error
	var k *big.Int
	var r *big.Int
	var d, s big.Int
Retry:
	if _, err = io.ReadFull(rand, kRaw); err != nil {
		return nil, errx.PrefixText("gogost/gost3410.PrivateKey.SignDigest", err)
	}
	k = bytes2big(kRaw)
	k.Mod(k, prv.C.Q)
	if k.Cmp(zero) == 0 {
		goto Retry
	}
	r, _, err = prv.C.expBase(k)
	if err != nil {
		return nil, errx.PrefixText("gogost/gost3410.PrivateKey.SignDigest", err)
	}
	r.Mod(r, prv.C.Q)
	if r.Cmp(zero) == 0 {
		goto Retry
	}
	d.Mul(prv.Key, r)
	k.Mul(k, e)
	s.Add(&d, k)
	s.Mod(&s, prv.C.Q)
	if s.Cmp(zero) == 0 {
		goto Retry
	}
	pointSize := prv.C.PointSize()
	return append(
		pad(s.Bytes(), pointSize),
		pad(r.Bytes(), pointSize)...,
	), nil
}

// Sign подписывает дайджест для совместимости с crypto.Signer. opts не используется.
func (prv *PrivateKey) Sign(
	rand io.Reader, digest []byte, opts crypto.SignerOpts,
) ([]byte, error) {
	return prv.SignDigest(digest, rand)
}

// Public возвращает открытый ключ для совместимости с crypto.Signer.
func (prv *PrivateKey) Public() crypto.PublicKey {
	pub, err := prv.PublicKey()
	if err != nil {
		panic(err)
	}
	return pub
}

// PrivateKeyReverseDigest адаптирует подпись для протоколов, разворачивающих дайджесты.
type PrivateKeyReverseDigest struct {
	Prv *PrivateKey
}

func (prv *PrivateKeyReverseDigest) Public() crypto.PublicKey {
	return prv.Prv.Public()
}

func (prv *PrivateKeyReverseDigest) Sign(
	rand io.Reader, digest []byte, opts crypto.SignerOpts,
) ([]byte, error) {
	dgst := make([]byte, len(digest))
	for i := range len(digest) {
		dgst[i] = digest[len(digest)-i-1]
	}
	return prv.Prv.Sign(rand, dgst, opts)
}

// PrivateKeyReverseDigestAndSignature адаптирует подпись для протоколов,
// разворачивающих и дайджесты, и подписи.
type PrivateKeyReverseDigestAndSignature struct {
	Prv *PrivateKey
}

func (prv *PrivateKeyReverseDigestAndSignature) Public() crypto.PublicKey {
	return prv.Prv.Public()
}

func (prv *PrivateKeyReverseDigestAndSignature) Sign(
	rand io.Reader, digest []byte, opts crypto.SignerOpts,
) ([]byte, error) {
	dgst := make([]byte, len(digest))
	for i := range len(digest) {
		dgst[i] = digest[len(digest)-i-1]
	}
	sign, err := prv.Prv.Sign(rand, dgst, opts)
	if err != nil {
		return sign, err
	}
	reverse(sign)
	return sign, err
}
