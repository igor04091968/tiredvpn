package gost3410

import (
	"crypto"
	"errors"
	"math/big"

	"gitverse.ru/uzer_007/gogost/v3/internal/errx"
)

// PublicKey представляет открытый ключ ГОСТ Р 34.10, привязанный к кривой.
type PublicKey struct {
	C    *Curve
	X, Y *big.Int
}

// NewPublicKeyLE разбирает открытый ключ в формате LE(X)||LE(Y).
func NewPublicKeyLE(c *Curve, raw []byte) (*PublicKey, error) {
	if c == nil || c.P == nil || c.Q == nil || c.Co == nil {
		return nil, errors.New("gogost/gost3410: Некорректная кривая")
	}
	pointSize := c.PointSize()
	key := make([]byte, 2*pointSize)
	if len(raw) != len(key) {
		return nil, errors.New("gogost/gost3410: длина ключа не равна " + errx.Int(len(key)))
	}
	for i := range len(key) {
		key[i] = raw[len(raw)-i-1]
	}
	pub := &PublicKey{
		c,
		bytes2big(key[pointSize : 2*pointSize]),
		bytes2big(key[:pointSize]),
	}
	if err := pub.Validate(); err != nil {
		return nil, err
	}
	return pub, nil
}

// NewPublicKeyBE разбирает открытый ключ в формате BE(X)||BE(Y).
func NewPublicKeyBE(c *Curve, raw []byte) (*PublicKey, error) {
	if c == nil || c.P == nil || c.Q == nil || c.Co == nil {
		return nil, errors.New("gogost/gost3410: Некорректная кривая")
	}
	pointSize := c.PointSize()
	if len(raw) != 2*pointSize {
		return nil, errors.New("gogost/gost3410: длина ключа не равна " + errx.Int(2*pointSize))
	}
	pub := &PublicKey{
		c,
		bytes2big(raw[:pointSize]),
		bytes2big(raw[pointSize:]),
	}
	if err := pub.Validate(); err != nil {
		return nil, err
	}
	return pub, nil
}

// Validate checks the coordinate range, curve membership and prime-order
// subgroup membership. Call it again if exported key fields were modified.
func (pub *PublicKey) Validate() error {
	if pub == nil || pub.C == nil || pub.C.P == nil || pub.C.Q == nil || pub.C.Co == nil ||
		pub.X == nil || pub.Y == nil || pub.C.P.Sign() <= 0 || pub.C.Q.Sign() <= 0 || pub.C.Co.Sign() <= 0 {
		return errors.New("gogost/gost3410: Некорректный открытый ключ")
	}
	c := pub.C
	if pub.X.Sign() < 0 || pub.Y.Sign() < 0 || pub.X.Cmp(c.P) >= 0 || pub.Y.Cmp(c.P) >= 0 {
		return errors.New("gogost/gost3410: Точка не принадлежит кривой")
	}
	checkSubgroup := c.Co.Cmp(bigInt1) != 0
	if checkSubgroup && c.fixedState.hasValidatedPoint(c, pub.X, pub.Y) {
		return nil
	}
	if !c.Contains(pub.X, pub.Y) {
		return errors.New("gogost/gost3410: Точка не принадлежит кривой")
	}
	if checkSubgroup {
		if !c.pointInSubgroup(pub.X, pub.Y) {
			return errors.New("gogost/gost3410: Точка не принадлежит подгруппе")
		}
		c.fixedState.rememberValidatedPoint(c, pub.X, pub.Y)
	}
	return nil
}

// pointInSubgroup computes [Q]P using public-data Jacobian arithmetic and
// checks the projective identity without a costly affine inversion.
func (c *Curve) pointInSubgroup(x, y *big.Int) bool {
	if result, used := c.fixedState.pointInSubgroup(c, x, y); used {
		return result
	}
	return c.pointInSubgroupGeneric(x, y)
}

func (c *Curve) pointInSubgroupGeneric(x, y *big.Int) bool {
	var table [16]jacobianPoint
	var result jacobianPoint
	var scratch jacobianScratch
	table[0].setInfinity()
	table[1].setAffine(x, y)
	for i := 2; i < len(table); i++ {
		table[i].set(&table[i-1])
		c.jacobianAdd(&table[i], &table[1], &scratch)
	}
	result.setInfinity()
	for window := (c.Q.BitLen() + 3) / 4; window > 0; {
		window--
		for range 4 {
			c.jacobianDouble(&result, &scratch)
		}
		index := 0
		for bit := 0; bit < 4; bit++ {
			index |= int(c.Q.Bit(window*4+bit)) << bit
		}
		if index != 0 {
			c.jacobianAdd(&result, &table[index], &scratch)
		}
	}
	return result.isInfinity()
}

// NewPublicKey является псевдонимом NewPublicKeyLE.
func NewPublicKey(c *Curve, raw []byte) (*PublicKey, error) {
	return NewPublicKeyLE(c, raw)
}

// RawLE возвращает открытый ключ в формате LE(X)||LE(Y).
func (pub *PublicKey) RawLE() []byte {
	pointSize := pub.C.PointSize()
	raw := append(
		pad(pub.Y.Bytes(), pointSize),
		pad(pub.X.Bytes(), pointSize)...,
	)
	reverse(raw)
	return raw
}

// RawBE возвращает открытый ключ в формате BE(X)||BE(Y).
func (pub *PublicKey) RawBE() []byte {
	pointSize := pub.C.PointSize()
	return append(
		pad(pub.X.Bytes(), pointSize),
		pad(pub.Y.Bytes(), pointSize)...,
	)
}

// Raw является псевдонимом RawLE.
func (pub *PublicKey) Raw() []byte {
	return pub.RawLE()
}

// VerifyDigest проверяет подпись S||R для переданного дайджеста.
func (pub *PublicKey) VerifyDigest(digest, signature []byte) (bool, error) {
	pointSize := pub.C.PointSize()
	if len(signature) != 2*pointSize {
		return false, errors.New("gogost/gost3410: длина подписи " + errx.Int(len(signature)) + ", ожидалось " + errx.Int(2*pointSize))
	}
	s := bytes2big(signature[:pointSize])
	r := bytes2big(signature[pointSize:])
	if r.Cmp(zero) <= 0 ||
		r.Cmp(pub.C.Q) >= 0 ||
		s.Cmp(zero) <= 0 ||
		s.Cmp(pub.C.Q) >= 0 {
		return false, nil
	}
	e := bytes2big(digest)
	e.Mod(e, pub.C.Q)
	if e.Cmp(zero) == 0 {
		e.SetInt64(1)
	}
	var v, z1, z2 big.Int
	if v.ModInverse(e, pub.C.Q) == nil {
		return false, nil
	}
	z1.Mul(s, &v)
	z1.Mod(&z1, pub.C.Q)
	z2.Mul(r, &v)
	z2.Mod(&z2, pub.C.Q)
	z2.Sub(pub.C.Q, &z2)
	x, _, err := pub.C.expDoubleBaseAndPoint(&z1, &z2, pub.X, pub.Y)
	if err != nil {
		return false, nil
	}
	x.Mod(x, pub.C.Q)
	return x.Cmp(r) == 0, nil
}

// Equal сообщает, совпадает ли theirKey с этим открытым ключом ГОСТ Р 34.10.
func (our *PublicKey) Equal(theirKey crypto.PublicKey) bool {
	their, ok := theirKey.(*PublicKey)
	if !ok {
		return false
	}
	return our.X.Cmp(their.X) == 0 && our.Y.Cmp(their.Y) == 0 && our.C.Equal(their.C)
}

// PublicKeyReverseDigest адаптирует проверку для протоколов, разворачивающих дайджесты.
type PublicKeyReverseDigest struct {
	Pub *PublicKey
}

func (pub PublicKeyReverseDigest) VerifyDigest(
	digest, signature []byte,
) (bool, error) {
	dgst := make([]byte, len(digest))
	for i := range len(digest) {
		dgst[i] = digest[len(digest)-i-1]
	}
	return pub.Pub.VerifyDigest(dgst, signature)
}

func (pub PublicKeyReverseDigest) Equal(theirKey crypto.PublicKey) bool {
	return pub.Pub.Equal(theirKey)
}

// PublicKeyReverseDigestAndSignature адаптирует проверку для протоколов,
// разворачивающих и дайджесты, и подписи.
type PublicKeyReverseDigestAndSignature struct {
	Pub *PublicKey
}

func (pub PublicKeyReverseDigestAndSignature) VerifyDigest(
	digest, signature []byte,
) (bool, error) {
	dgst := make([]byte, len(digest))
	for i := range len(digest) {
		dgst[i] = digest[len(digest)-i-1]
	}
	sign := make([]byte, len(signature))
	for i := range len(signature) {
		sign[i] = signature[len(signature)-i-1]
	}
	return pub.Pub.VerifyDigest(dgst, sign)
}

func (pub PublicKeyReverseDigestAndSignature) Equal(theirKey crypto.PublicKey) bool {
	return pub.Pub.Equal(theirKey)
}
