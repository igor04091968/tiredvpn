package gost3410

import (
	"bytes"
	"math/big"
	"sync"
	"testing"
)

func TestPrivateKeyRejectsNonCanonicalScalar(t *testing.T) {
	curve := CurveIdtc26gost341012256paramSetA()
	size := curve.PointSize()
	invalid := [][]byte{
		make([]byte, size),
		curve.Q.FillBytes(make([]byte, size)),
	}
	if next := new(big.Int).Add(curve.Q, bigInt1); next.BitLen() <= size*8 {
		invalid = append(invalid, next.FillBytes(make([]byte, size)))
	}
	for _, raw := range invalid {
		if _, err := NewPrivateKeyBE(curve, raw); err == nil {
			t.Fatalf("accepted BE scalar %x", raw)
		}
		reversed := bytes.Clone(raw)
		reverse(reversed)
		if _, err := NewPrivateKeyLE(curve, reversed); err == nil {
			t.Fatalf("accepted LE scalar %x", reversed)
		}
	}
	if _, err := NewPrivateKeyBE(nil, make([]byte, size)); err == nil {
		t.Fatal("accepted nil curve")
	}
	one := bigInt1.FillBytes(make([]byte, size))
	if _, err := NewPrivateKeyBE(curve, one); err != nil {
		t.Fatalf("rejected scalar one: %v", err)
	}
}

func TestGenPrivateKeyRejectsInvalidSamples(t *testing.T) {
	curve := CurveIdtc26gost341012256paramSetA()
	size := (curve.Q.BitLen() + 7) / 8
	valid := make([]byte, size)
	valid[size-1] = 1
	reader := bytes.NewReader(append(make([]byte, size), valid...))
	key, err := GenPrivateKey(curve, reader)
	if err != nil || key.Key.Cmp(bigInt1) != 0 {
		t.Fatalf("sample rejection failed: key=%v err=%v", key, err)
	}
	if _, err := GenPrivateKey(curve, bytes.NewReader(make([]byte, size*128))); err == nil {
		t.Fatal("accepted repeated zero samples")
	}
	if _, err := GenPrivateKey(nil, reader); err == nil {
		t.Fatal("accepted nil curve")
	}
}

func TestPublicKeyRejectsInvalidPoint(t *testing.T) {
	curve := CurveIdtc26gost341012256paramSetA()
	size := curve.PointSize()
	if _, err := NewPublicKeyBE(curve, make([]byte, size*2)); err == nil {
		t.Fatal("accepted zero coordinates")
	}
	if _, err := NewPublicKeyLE(nil, make([]byte, size*2)); err == nil {
		t.Fatal("accepted nil curve")
	}
	pub := &PublicKey{C: curve, X: new(big.Int).Set(curve.P), Y: big.NewInt(1)}
	if err := pub.Validate(); err == nil {
		t.Fatal("accepted noncanonical coordinate")
	}
	if curve.Co.Cmp(bigInt1) == 0 {
		t.Skip("curve has no nontrivial cofactor")
	}
	for i := int64(0); i < 64; i++ {
		x := big.NewInt(i)
		var y2, tmp big.Int
		y2.Mul(x, x)
		y2.Add(&y2, curve.A)
		y2.Mul(&y2, x)
		tmp.Set(curve.B)
		y2.Add(&y2, &tmp)
		y2.Mod(&y2, curve.P)
		y := new(big.Int).ModSqrt(&y2, curve.P)
		if y == nil || curve.pointInSubgroup(x, y) {
			continue
		}
		pub = &PublicKey{C: curve, X: x, Y: y}
		if err := pub.Validate(); err == nil {
			t.Fatal("accepted point outside prime-order subgroup")
		}
		if _, err := NewPublicKeyBE(curve, pub.RawBE()); err == nil {
			t.Fatal("BE constructor accepted point outside subgroup")
		}
		if _, err := NewPublicKeyLE(curve, pub.RawLE()); err == nil {
			t.Fatal("LE constructor accepted point outside subgroup")
		}
		return
	}
	t.Fatal("failed to find an on-curve point outside the prime-order subgroup")
}

func TestFixedSubgroupCheckMatchesGeneric(t *testing.T) {
	curves := []*Curve{
		CurveIdtc26gost341012256paramSetA(),
		CurveIdtc26gost341012256paramSetB(),
		CurveIdtc26gost341012256paramSetC(),
		CurveIdtc26gost341012256paramSetD(),
		CurveIdtc26gost341012512paramSetA(),
		CurveIdtc26gost341012512paramSetB(),
		CurveIdtc26gost341012512paramSetC(),
	}
	checked := 0
	for _, curve := range curves {
		if curve.Co.Cmp(bigInt1) == 0 {
			continue
		}
		checked++
		if !curve.pointInSubgroup(curve.X, curve.Y) || !curve.pointInSubgroupGeneric(curve.X, curve.Y) {
			t.Fatalf("%s: base point outside subgroup", curve.Name)
		}
		found := 0
		for i := int64(0); i < 24 && found < 3; i++ {
			x := big.NewInt(i)
			var y2 big.Int
			y2.Mul(x, x)
			y2.Add(&y2, curve.A)
			y2.Mul(&y2, x)
			y2.Add(&y2, curve.B)
			y2.Mod(&y2, curve.P)
			y := new(big.Int).ModSqrt(&y2, curve.P)
			if y == nil {
				continue
			}
			found++
			if got, want := curve.pointInSubgroup(x, y), curve.pointInSubgroupGeneric(x, y); got != want {
				t.Fatalf("%s: subgroup mismatch at x=%d: got %v, want %v", curve.Name, i, got, want)
			}
		}
		if found < 3 {
			t.Fatalf("%s: insufficient on-curve test points", curve.Name)
		}
	}
	if checked == 0 {
		t.Fatal("no cofactor curves were checked")
	}
}

func TestSubgroupCheckRejectsTorsionPoints(t *testing.T) {
	for _, curve := range []*Curve{
		CurveIdtc26gost341012256paramSetA(),
		CurveIdtc26gost341012512paramSetC(),
	} {
		found := false
		for candidate := int64(0); candidate < 64; candidate++ {
			x := big.NewInt(candidate)
			var y2 big.Int
			y2.Mul(x, x)
			y2.Add(&y2, curve.A)
			y2.Mul(&y2, x)
			y2.Add(&y2, curve.B)
			y2.Mod(&y2, curve.P)
			y := new(big.Int).ModSqrt(&y2, curve.P)
			if y == nil || curve.pointInSubgroupGeneric(x, y) {
				continue
			}
			torsionX, torsionY, err := curve.Exp(curve.Q, x, y)
			if err != nil {
				t.Fatalf("%s: compute torsion point: %v", curve.Name, err)
			}
			if !curve.Contains(torsionX, torsionY) {
				t.Fatalf("%s: torsion point is off curve", curve.Name)
			}
			if curve.pointInSubgroup(torsionX, torsionY) ||
				(&PublicKey{C: curve, X: torsionX, Y: torsionY}).Validate() == nil {
				t.Fatalf("%s: accepted a nonzero torsion point", curve.Name)
			}
			found = true
			break
		}
		if !found {
			t.Fatalf("%s: no nonzero torsion point found", curve.Name)
		}
	}
}

func TestSubgroupOrderCheckMatchesFullEdwardsMultiply(t *testing.T) {
	curve256 := CurveIdtc26gost341012256paramSetA()
	checkSubgroupOrderPath(t, curve256, curve256.fixedState.get256(curve256))
	curve512 := CurveIdtc26gost341012512paramSetC()
	checkSubgroupOrderPath(t, curve512, curve512.fixedState.get512(curve512))
}

func checkSubgroupOrderPath[L fixedLimbs](t *testing.T, curve *Curve, fixed *fixedCurve[L]) {
	t.Helper()
	if fixed == nil || !fixed.edwards {
		t.Fatal("missing Edwards backend")
	}
	checked := 0
	for candidate := int64(0); candidate < 128 && checked < 16; candidate++ {
		x := big.NewInt(candidate)
		var y2 big.Int
		y2.Mul(x, x)
		y2.Add(&y2, curve.A)
		y2.Mul(&y2, x)
		y2.Add(&y2, curve.B)
		y2.Mod(&y2, curve.P)
		y := new(big.Int).ModSqrt(&y2, curve.P)
		if y == nil {
			continue
		}
		point := fixed.edwardsFromWeierstrass(fixed.p.fromBig(x), fixed.p.fromBig(y))
		if fixedZeroMask(point.z) != 0 {
			continue
		}
		checked++
		got := fixed.edwardsMultiplySubgroup(point)
		want := fixed.edwardsMultiplySmall(point, curve.Q)
		gotIdentity := fixedZeroMask(got.z) == 0 && fixedZeroMask(got.x) != 0 && fixedEqualMask(got.y, got.z) != 0
		wantIdentity := fixedZeroMask(want.z) == 0 && fixedZeroMask(want.x) != 0 && fixedEqualMask(want.y, want.z) != 0
		if gotIdentity != wantIdentity {
			t.Fatalf("%s: subgroup mismatch for x=%d", curve.Name, candidate)
		}
		if fixedZeroMask(got.z) != 0 && fixedZeroMask(want.z) != 0 &&
			(fixedEqualMask(fixed.p.mul(got.x, want.z), fixed.p.mul(want.x, got.z)) == 0 ||
				fixedEqualMask(fixed.p.mul(got.y, want.z), fixed.p.mul(want.y, got.z)) == 0) {
			t.Fatalf("%s: projective result mismatch for x=%d", curve.Name, candidate)
		}
	}
	if checked < 16 {
		t.Fatalf("%s: tested only %d on-curve points", curve.Name, checked)
	}
}

func TestValidatedPointCacheRejectsModifiedKeyAndDomain(t *testing.T) {
	curve := CurveIdtc26gost341012256paramSetA()
	pub := &PublicKey{C: curve, X: new(big.Int).Set(curve.X), Y: new(big.Int).Set(curve.Y)}
	if err := pub.Validate(); err != nil {
		t.Fatal(err)
	}
	if !curve.fixedState.hasValidatedPoint(curve, pub.X, pub.Y) {
		t.Fatal("valid public point was not cached")
	}

	// Factories return mutable copies of the domain, sharing only the
	// immutable fixed backend. A modified domain must never reuse its cache.
	curve.A.Add(curve.A, bigInt1)
	if curve.fixedState.hasValidatedPoint(curve, pub.X, pub.Y) {
		t.Fatal("reused cached point after domain mutation")
	}
	if err := pub.Validate(); err == nil {
		t.Fatal("accepted a cached point on a modified curve")
	}
	curve.A.Sub(curve.A, bigInt1)

	pub.X.Add(pub.X, bigInt1)
	if curve.fixedState.hasValidatedPoint(curve, pub.X, pub.Y) {
		t.Fatal("reused cached point after coordinate mutation")
	}
	if err := pub.Validate(); err == nil {
		t.Fatal("accepted a modified cached point")
	}
}

func TestValidatedPointCacheAcrossCurveClones(t *testing.T) {
	for _, tc := range []struct {
		name    string
		factory func() *Curve
	}{
		{"256A", CurveIdtc26gost341012256paramSetA},
		{"512C", CurveIdtc26gost341012512paramSetC},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first := tc.factory()
			second := tc.factory()
			if first.fixedState != second.fixedState {
				t.Fatal("named curves do not share an immutable backend")
			}
			pub := &PublicKey{C: first, X: new(big.Int).Set(first.X), Y: new(big.Int).Set(first.Y)}
			if err := pub.Validate(); err != nil {
				t.Fatal(err)
			}
			if !second.fixedState.hasValidatedPoint(second, pub.X, pub.Y) {
				t.Fatal("validated point was not available to another curve clone")
			}
		})
	}
}

func TestValidatedPointCacheConcurrent(t *testing.T) {
	const workers = 32
	var keys [workers]*PublicKey
	for i := range keys {
		curve := CurveIdtc26gost341012256paramSetA()
		pub, err := (&PrivateKey{C: curve, Key: big.NewInt(int64(i + 1))}).PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		keys[i] = pub
	}
	var wg sync.WaitGroup
	errors := make(chan error, workers)
	for _, pub := range keys {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 8 {
				if err := pub.Validate(); err != nil {
					errors <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		t.Errorf("concurrent validation failed: %v", err)
	}
}
