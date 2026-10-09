package gost3410

import (
	"math/big"

	"gitverse.ru/uzer_007/gogost/v3/internal/errx"
)

// KEK вырабатывает общий ключ шифрования ключей по схеме VKO.
func (prv *PrivateKey) KEK(pub *PublicKey, ukm *big.Int) ([]byte, error) {
	if key, err, used := prv.C.fixedState.vko(prv.C, prv.Key, ukm, pub.X, pub.Y); used {
		if err != nil {
			return nil, errx.PrefixText("gogost/gost3410.PrivateKey.KEK", err)
		}
		return key, nil
	}
	// [d]P followed by [UKM*cofactor] is exactly
	// [d*UKM*cofactor]P. Combining the scalars avoids constructing a second
	// arbitrary-point table and, more importantly, avoids a second projective
	// to affine inversion. Do not reduce the combined scalar modulo Q here:
	// callers may pass an on-curve point which has not been independently
	// proven to be in the prime-order subgroup, and the cofactor is what clears
	// that component.
	var scalar big.Int
	scalar.Mul(prv.Key, ukm)
	scalar.Mul(&scalar, prv.C.Co)
	keyX, keyY, err := prv.C.Exp(&scalar, pub.X, pub.Y)
	if err != nil {
		return nil, errx.PrefixText("gogost/gost3410.PrivateKey.KEK", err)
	}
	pk := PublicKey{prv.C, keyX, keyY}
	return pk.Raw(), nil
}
