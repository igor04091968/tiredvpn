package gost3410

import (
	"bytes"
	"math/big"
	"testing"
)

func legacyTwoStageKEK(prv *PrivateKey, pub *PublicKey, ukm *big.Int) ([]byte, error) {
	keyX, keyY, err := prv.C.Exp(prv.Key, pub.X, pub.Y)
	if err != nil {
		return nil, err
	}
	var multiplier big.Int
	multiplier.Mul(ukm, prv.C.Co)
	if multiplier.Cmp(bigInt1) != 0 {
		keyX, keyY, err = prv.C.Exp(&multiplier, keyX, keyY)
		if err != nil {
			return nil, err
		}
	}
	return (&PublicKey{C: prv.C, X: keyX, Y: keyY}).Raw(), nil
}

func TestCombinedVKOAgainstTwoStage(t *testing.T) {
	curves := []struct {
		name string
		new  func() *Curve
	}{
		{"2001-cc", CurveGostR34102001ParamSetcc},
		{"2001-test", CurveIdGostR34102001TestParamSet},
		{"2012-256-A", CurveIdtc26gost341012256paramSetA},
		{"2012-256-B", CurveIdtc26gost341012256paramSetB},
		{"2012-256-C", CurveIdtc26gost341012256paramSetC},
		{"2012-256-D", CurveIdtc26gost341012256paramSetD},
		{"2012-512-test", CurveIdtc26gost341012512paramSetTest},
		{"2012-512-A", CurveIdtc26gost341012512paramSetA},
		{"2012-512-B", CurveIdtc26gost341012512paramSetB},
		{"2012-512-C", CurveIdtc26gost341012512paramSetC},
	}
	largeUKM := new(big.Int).Lsh(big.NewInt(1), 520)
	largeUKM.Add(largeUKM, big.NewInt(0x12345))
	ukms := []*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(2), largeUKM}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			curve := tc.new()
			size := curve.PointSize()
			privateRaw := make([]byte, size)
			peerRaw := make([]byte, size)
			for i := range size {
				privateRaw[i] = byte(i*17 + 3)
				peerRaw[i] = byte(i*29 + 5)
			}
			privateScalar := new(big.Int).SetBytes(privateRaw)
			privateScalar.Mod(privateScalar, new(big.Int).Sub(curve.Q, bigInt1))
			privateScalar.Add(privateScalar, bigInt1)
			prv, err := NewPrivateKeyBE(curve, privateScalar.FillBytes(make([]byte, size)))
			if err != nil {
				t.Fatal(err)
			}
			peerScalar := new(big.Int).SetBytes(peerRaw)
			peerScalar.Mod(peerScalar, new(big.Int).Sub(curve.Q, bigInt1))
			peerScalar.Add(peerScalar, bigInt1)
			peer, err := NewPrivateKeyBE(curve, peerScalar.FillBytes(make([]byte, size)))
			if err != nil {
				t.Fatal(err)
			}
			pub, err := peer.PublicKey()
			if err != nil {
				t.Fatal(err)
			}
			for _, ukm := range ukms {
				want, wantErr := legacyTwoStageKEK(prv, pub, ukm)
				got, gotErr := prv.KEK(pub, ukm)
				if (gotErr != nil) != (wantErr != nil) {
					t.Fatalf("UKM %x: error = %v, legacy error = %v", ukm, gotErr, wantErr)
				}
				if gotErr == nil && !bytes.Equal(got, want) {
					t.Fatalf("UKM %x: combined VKO differs from two-stage result", ukm)
				}
			}
		})
	}
}
