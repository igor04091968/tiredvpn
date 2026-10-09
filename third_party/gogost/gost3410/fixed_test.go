package gost3410

import (
	"math/big"
	"math/rand"
	"testing"
	"unsafe"
)

func builtinCurveTests() []struct {
	name string
	new  func() *Curve
} {
	return []struct {
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
}

func testMontDomain[L fixedLimbs](t *testing.T, modulus *big.Int) {
	t.Helper()
	domain, ok := newMontDomain[L](modulus)
	if !ok {
		t.Fatal("newMontDomain rejected valid modulus")
	}
	values := []*big.Int{
		new(big.Int),
		big.NewInt(1),
		big.NewInt(2),
		new(big.Int).Sub(modulus, big.NewInt(2)),
		new(big.Int).Sub(modulus, big.NewInt(1)),
	}
	random := rand.New(rand.NewSource(0x3410))
	for range 32 {
		value := new(big.Int).Rand(random, modulus)
		values = append(values, value)
	}

	for _, x := range values {
		xMont := domain.fromBig(x)
		if got := domain.toBig(xMont); got.Cmp(x) != 0 {
			t.Fatalf("roundtrip(%x) = %x", x, got)
		}
		if x.Sign() != 0 {
			wantInverse := new(big.Int).ModInverse(x, modulus)
			gotInverse := domain.toBig(domain.invert(xMont))
			if gotInverse.Cmp(wantInverse) != 0 {
				t.Fatalf("inverse(%x) = %x, want %x", x, gotInverse, wantInverse)
			}
		}
		for _, y := range values {
			yMont := domain.fromBig(y)
			want := new(big.Int).Add(x, y)
			want.Mod(want, modulus)
			if got := domain.toBig(domain.add(xMont, yMont)); got.Cmp(want) != 0 {
				t.Fatalf("add(%x,%x) = %x, want %x", x, y, got, want)
			}
			want.Sub(x, y)
			want.Mod(want, modulus)
			if got := domain.toBig(domain.sub(xMont, yMont)); got.Cmp(want) != 0 {
				t.Fatalf("sub(%x,%x) = %x, want %x", x, y, got, want)
			}
			want.Mul(x, y)
			want.Mod(want, modulus)
			if got := domain.toBig(domain.mul(xMont, yMont)); got.Cmp(want) != 0 {
				t.Fatalf("mul(%x,%x) = %x, want %x", x, y, got, want)
			}
		}
	}
}

func TestFixedMontgomeryDomains(t *testing.T) {
	for _, tc := range builtinCurveTests() {
		t.Run(tc.name, func(t *testing.T) {
			curve := tc.new()
			if curve.P.BitLen() <= 256 {
				testMontDomain[limbs256](t, curve.P)
				testMontDomain[limbs256](t, curve.Q)
				return
			}
			testMontDomain[limbs512](t, curve.P)
			testMontDomain[limbs512](t, curve.Q)
		})
	}
}

func testFixedPoints[L fixedLimbs](t *testing.T, curve *Curve, fixed *fixedCurve[L]) {
	t.Helper()
	legacy := curve.clone()
	legacy.fixedState = nil
	for scalar := int64(1); scalar <= 19; scalar++ {
		degree := big.NewInt(scalar)
		wantX, wantY, err := legacy.Exp(degree, legacy.X, legacy.Y)
		if err != nil {
			t.Fatal(err)
		}
		gotX, gotY, err := fixed.expPoint(degree, curve.X, curve.Y)
		if err != nil {
			t.Fatal(err)
		}
		if gotX.Cmp(wantX) != 0 || gotY.Cmp(wantY) != 0 {
			t.Fatalf("scalar %d fixed point differs from legacy", scalar)
		}
	}

	degree := new(big.Int).Sub(curve.Q, big.NewInt(1))
	wantX, wantY, err := legacy.Exp(degree, legacy.X, legacy.Y)
	if err != nil {
		t.Fatal(err)
	}
	gotX, gotY, err := fixed.expPoint(degree, curve.X, curve.Y)
	if err != nil {
		t.Fatal(err)
	}
	if gotX.Cmp(wantX) != 0 || gotY.Cmp(wantY) != 0 {
		t.Fatal("Q-1 fixed point differs from legacy")
	}

	gotX, gotY, err = fixed.expBase(degree)
	if err != nil {
		t.Fatal(err)
	}
	if gotX.Cmp(wantX) != 0 || gotY.Cmp(wantY) != 0 {
		t.Fatal("fixed-base comb differs from legacy")
	}

	random := rand.New(rand.NewSource(0x34102012))
	for range 24 {
		degree := new(big.Int).Rand(random, curve.Q)
		if degree.Sign() == 0 {
			degree.SetInt64(1)
		}
		pointDegree := new(big.Int).Rand(random, curve.Q)
		if pointDegree.Sign() == 0 {
			pointDegree.SetInt64(1)
		}
		pointX, pointY, err := legacy.Exp(pointDegree, legacy.X, legacy.Y)
		if err != nil {
			t.Fatal(err)
		}
		wantX, wantY, err := legacy.Exp(degree, pointX, pointY)
		if err != nil {
			t.Fatal(err)
		}
		gotX, gotY, err := fixed.expPoint(degree, pointX, pointY)
		if err != nil {
			t.Fatal(err)
		}
		if gotX.Cmp(wantX) != 0 || gotY.Cmp(wantY) != 0 {
			t.Fatal("random arbitrary-point multiplication differs from legacy")
		}

		second := new(big.Int).Rand(random, curve.Q)
		wantX, wantY, err = legacy.expDoubleBaseAndPoint(degree, second, pointX, pointY)
		if err != nil {
			t.Fatal(err)
		}
		gotX, gotY, err = fixed.expDoublePublic(degree, second, pointX, pointY)
		if err != nil {
			t.Fatal(err)
		}
		if gotX.Cmp(wantX) != 0 || gotY.Cmp(wantY) != 0 {
			t.Fatal("random double-scalar multiplication differs from legacy")
		}
	}
}

func testFixedEdwardsTableLimit[L fixedLimbs](t *testing.T, fixed *fixedCurve[L], limit uintptr) {
	t.Helper()
	if !fixed.edwards {
		return
	}
	fixed.baseOnce.Do(fixed.buildBaseTable)
	size := uintptr(len(fixed.edBaseTable)) * unsafe.Sizeof(fixed.edBaseTable[0])
	if size != limit {
		t.Fatalf("mixed Edwards fixed-base table is %d bytes, want %d", size, limit)
	}
}

func TestFixedPointBackends(t *testing.T) {
	for _, tc := range builtinCurveTests() {
		t.Run(tc.name, func(t *testing.T) {
			curve := tc.new()
			domain := snapshotCurveDomain(curve)
			if curve.P.BitLen() <= 256 {
				fixed, ok := newFixedCurve[limbs256](&domain)
				if !ok {
					t.Fatal("failed to build 256-bit backend")
				}
				testFixedPoints(t, curve, fixed)
				testFixedEdwardsTableLimit(t, fixed, 96<<10)
				return
			}
			fixed, ok := newFixedCurve[limbs512](&domain)
			if !ok {
				t.Fatal("failed to build 512-bit backend")
			}
			testFixedPoints(t, curve, fixed)
			testFixedEdwardsTableLimit(t, fixed, 384<<10)
		})
	}
}

func TestFixedBackendRejectsMutatedDomain(t *testing.T) {
	curve := CurveIdtc26gost341012256paramSetA()
	state := newFixedBackendState(curve)
	if state.get256(curve) == nil {
		t.Fatal("canonical curve did not enable fixed backend")
	}
	curve.B.Add(curve.B, bigInt1)
	if state.get256(curve) != nil {
		t.Fatal("fixed backend accepted a mutated full-domain fingerprint")
	}
}

func TestFixedSignVerifyAllDomains(t *testing.T) {
	for _, tc := range builtinCurveTests() {
		t.Run(tc.name, func(t *testing.T) {
			curve := tc.new()
			raw := make([]byte, curve.PointSize())
			for i := range raw {
				raw[i] = byte(i + 1)
			}
			private, err := NewPrivateKeyBE(curve, raw)
			if err != nil {
				t.Fatal(err)
			}
			public, err := private.PublicKey()
			if err != nil {
				t.Fatal(err)
			}
			digest := benchDigest(curve)
			signature, err := private.SignDigest(digest, &benchRand{})
			if err != nil {
				t.Fatal(err)
			}
			ok, err := public.VerifyDigest(digest, signature)
			if err != nil || !ok {
				t.Fatalf("fixed signature failed verification: ok=%v err=%v", ok, err)
			}
		})
	}
}
