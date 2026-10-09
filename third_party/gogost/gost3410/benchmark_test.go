package gost3410

import (
	"math/big"
	"testing"
)

var (
	bench3410Pub *PublicKey
	bench3410Sig []byte
	bench3410Key []byte
	bench3410OK  bool
)

type benchRand struct{ x byte }

func (r *benchRand) Read(p []byte) (int, error) {
	for i := range p {
		r.x += 17
		p[i] = r.x
	}
	return len(p), nil
}

func benchPrivateKey(b *testing.B, curve *Curve) *PrivateKey {
	b.Helper()
	raw := make([]byte, curve.PointSize())
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	prv, err := NewPrivateKey(curve, raw)
	if err != nil {
		b.Fatal(err)
	}
	return prv
}

func benchDigest(curve *Curve) []byte {
	digest := make([]byte, curve.PointSize())
	for i := range digest {
		digest[i] = byte(i*23 + 1)
	}
	return digest
}

func BenchmarkPublicKey(b *testing.B) {
	for _, tc := range []struct {
		name  string
		curve *Curve
	}{
		{"2001-256", CurveIdGostR34102001TestParamSet()},
		{"2012-256", CurveIdtc26gost34102012256paramSetA()},
		{"2012-512", CurveIdtc26gost34102012512paramSetA()},
	} {
		prv := benchPrivateKey(b, tc.curve)
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var err error
				bench3410Pub, err = prv.PublicKey()
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkPublicKeyValidation(b *testing.B) {
	curve := CurveIdtc26gost341012256paramSetA()
	bySlot := make(map[uint64]*PublicKey)
	var pair [2]*PublicKey
	for scalar := int64(1); scalar <= 1024 && pair[1] == nil; scalar++ {
		pub, err := (&PrivateKey{C: curve, Key: big.NewInt(scalar)}).PublicKey()
		if err != nil {
			b.Fatal(err)
		}
		slot := newValidatedPointKey(pub.X, pub.Y).slot()
		if previous := bySlot[slot]; previous != nil {
			pair = [2]*PublicKey{previous, pub}
		} else {
			bySlot[slot] = pub
		}
	}
	if pair[1] == nil {
		b.Fatal("could not find two keys sharing a validation-cache slot")
	}
	b.Run("cold-collision", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if err := pair[i&1].Validate(); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("warm", func(b *testing.B) {
		if err := pair[0].Validate(); err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if err := pair[0].Validate(); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkSignVerify(b *testing.B) {
	for _, tc := range []struct {
		name  string
		curve *Curve
	}{
		{"256", CurveIdtc26gost34102012256paramSetA()},
		{"512", CurveIdtc26gost34102012512paramSetA()},
	} {
		curve := tc.curve
		prv := benchPrivateKey(b, curve)
		pub, err := prv.PublicKey()
		if err != nil {
			b.Fatal(err)
		}
		digest := benchDigest(curve)
		rng := &benchRand{}
		sig, err := prv.SignDigest(digest, rng)
		if err != nil {
			b.Fatal(err)
		}
		b.Run("Sign-"+tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				bench3410Sig, err = prv.SignDigest(digest, rng)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("Verify-"+tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				bench3410OK, err = pub.VerifyDigest(digest, sig)
				if err != nil || !bench3410OK {
					b.Fatal("verify failed")
				}
			}
		})
	}
}

func BenchmarkVKO(b *testing.B) {
	for _, tc := range []struct {
		name  string
		curve *Curve
	}{
		{"256", CurveIdtc26gost34102012256paramSetA()},
		{"512", CurveIdtc26gost34102012512paramSetA()},
	} {
		curve := tc.curve
		prv := benchPrivateKey(b, curve)
		peer := benchPrivateKey(b, curve)
		pub, err := peer.PublicKey()
		if err != nil {
			b.Fatal(err)
		}
		ukm := NewUKM([]byte{1, 2, 3, 4, 5, 6, 7, 8})
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				bench3410Key, err = prv.KEK(pub, ukm)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkScalarMultiplication(b *testing.B) {
	for _, tc := range []struct {
		name  string
		curve *Curve
	}{
		{"256", CurveIdtc26gost34102012256paramSetA()},
		{"512", CurveIdtc26gost34102012512paramSetA()},
	} {
		curve := tc.curve
		prv := benchPrivateKey(b, curve)
		pub, err := prv.PublicKey()
		if err != nil {
			b.Fatal(err)
		}
		digest := benchDigest(curve)
		sig, err := prv.SignDigest(digest, &benchRand{})
		if err != nil {
			b.Fatal(err)
		}
		pointSize := curve.PointSize()
		s := bytes2big(sig[:pointSize])
		r := bytes2big(sig[pointSize:])
		e := bytes2big(digest)
		e.Mod(e, curve.Q)
		if e.Cmp(zero) == 0 {
			e.SetInt64(1)
		}
		var v, z1, z2 big.Int
		v.ModInverse(e, curve.Q)
		z1.Mul(s, &v)
		z1.Mod(&z1, curve.Q)
		z2.Mul(r, &v)
		z2.Mod(&z2, curve.Q)
		z2.Sub(curve.Q, &z2)

		b.Run("Base-"+tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var err error
				_, _, err = curve.expBase(prv.Key)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("Arbitrary-"+tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var err error
				_, _, err = curve.Exp(prv.Key, pub.X, pub.Y)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("DoubleScalar-"+tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var err error
				_, _, err = curve.expDoubleBaseAndPoint(&z1, &z2, pub.X, pub.Y)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkFixedBackendGate compares the immutable built-in backend with the
// compatibility math/big implementation on exactly the same domain. Keep the
// pairs together so benchstat can make the per-domain enablement decision.
func BenchmarkFixedBackendGate(b *testing.B) {
	for _, tc := range builtinCurveTests() {
		fixedCurve := tc.new()
		if fixedCurve.fixedState == nil {
			fixedCurve.fixedState = newFixedBackendState(fixedCurve)
		}
		legacyCurve := fixedCurve.clone()
		legacyCurve.fixedState = nil
		private := benchPrivateKey(b, fixedCurve)
		peer := benchPrivateKey(b, fixedCurve)
		public, err := peer.PublicKey()
		if err != nil {
			b.Fatal(err)
		}
		for _, backend := range []struct {
			name  string
			curve *Curve
		}{
			{"fixed", fixedCurve},
			{"legacy", legacyCurve},
		} {
			b.Run(tc.name+"/"+backend.name+"/base", func(b *testing.B) {
				b.ReportAllocs()
				if _, _, err := backend.curve.expBase(private.Key); err != nil {
					b.Fatal(err)
				}
				b.ResetTimer()
				for b.Loop() {
					if _, _, err := backend.curve.expBase(private.Key); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run(tc.name+"/"+backend.name+"/arbitrary", func(b *testing.B) {
				b.ReportAllocs()
				if _, _, err := backend.curve.Exp(private.Key, public.X, public.Y); err != nil {
					b.Fatal(err)
				}
				b.ResetTimer()
				for b.Loop() {
					if _, _, err := backend.curve.Exp(private.Key, public.X, public.Y); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
