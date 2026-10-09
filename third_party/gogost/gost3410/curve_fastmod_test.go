package gost3410

import (
	"errors"
	"math/big"
	"sync"
	"testing"
)

func TestCachedCurveFactoryIsolation(t *testing.T) {
	first := CurveIdtc26gost341012256paramSetA()
	second := CurveIdtc26gost341012256paramSetA()
	if first == second || first.P == second.P || first.X == second.X {
		t.Fatal("curve factory returned aliased public parameters")
	}
	if first.baseState == nil || first.baseState != second.baseState {
		t.Fatal("equal factory curves do not share immutable precompute state")
	}
	wantP := new(big.Int).Set(second.P)
	first.P.Sub(first.P, bigInt1)
	if second.P.Cmp(wantP) != 0 {
		t.Fatal("mutating one factory result changed another")
	}
	if first.baseState.get(first) != nil {
		t.Fatal("mutated curve reused precompute for the original domain")
	}
}

func TestCachedCurvePrecomputeConcurrentFirstUse(t *testing.T) {
	template := CurveIdtc26gost341012256paramSetA()
	factory := cachedCurveFactory(func() *Curve {
		curve, err := NewCurve(
			cloneBigInt(template.P), cloneBigInt(template.Q),
			cloneBigInt(template.A), cloneBigInt(template.B),
			cloneBigInt(template.X), cloneBigInt(template.Y),
			cloneBigInt(template.E), cloneBigInt(template.D), cloneBigInt(template.Co),
		)
		if err != nil {
			panic(err)
		}
		return curve
	})

	degree := new(big.Int).SetUint64(0x123456789abcdef)
	reference := factory()
	reference.baseState = nil
	wantX, wantY, err := reference.Exp(degree, reference.X, reference.Y)
	if err != nil {
		t.Fatal(err)
	}

	const workers = 16
	start := make(chan struct{})
	errors := make(chan error, workers)
	var wait sync.WaitGroup
	wait.Add(workers)
	for range workers {
		go func() {
			defer wait.Done()
			curve := factory()
			<-start
			x, y, err := curve.expBase(degree)
			if err == nil && (x.Cmp(wantX) != 0 || y.Cmp(wantY) != 0) {
				err = errPrecomputeMismatch
			}
			errors <- err
		}()
	}
	close(start)
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
}

var errPrecomputeMismatch = errors.New("concurrent precompute result mismatch")

func TestPseudoMersenneReduce256(t *testing.T) {
	curve := CurveIdtc26gost341012256paramSetA()
	values := []*big.Int{
		new(big.Int),
		new(big.Int).Sub(curve.P, bigInt1),
		new(big.Int).Set(curve.P),
		new(big.Int).Add(curve.P, bigInt1),
		new(big.Int).Mul(curve.P, curve.P),
	}

	state := uint64(0x9e3779b97f4a7c15)
	for byteLen := 1; byteLen <= 128; byteLen++ {
		raw := make([]byte, byteLen)
		for i := range raw {
			state ^= state << 7
			state ^= state >> 9
			state ^= state << 8
			raw[i] = byte(state)
		}
		value := new(big.Int).SetBytes(raw)
		if byteLen&1 != 0 {
			value.Neg(value)
		}
		values = append(values, value)
	}

	var scratch jacobianScratch
	for _, value := range values {
		want := new(big.Int).Mod(new(big.Int).Set(value), curve.P)
		got := new(big.Int).Set(value)
		curve.modJacobian(got, &scratch)
		if got.Cmp(want) != 0 {
			t.Fatalf("reduce(%x) = %x, want %x", value, got, want)
		}
	}
}

func TestPseudoMersenneReducerRejectsMutatedModulus(t *testing.T) {
	curve := CurveIdtc26gost341012256paramSetA()
	curve.P.Sub(curve.P, bigInt1)
	value := new(big.Int).Lsh(big.NewInt(1), 511)
	value.Add(value, big.NewInt(1234567))
	want := new(big.Int).Mod(new(big.Int).Set(value), curve.P)

	var scratch jacobianScratch
	curve.modJacobian(value, &scratch)
	if scratch.usePseudoMersenne {
		t.Fatal("optimized reducer accepted a mutated modulus")
	}
	if value.Cmp(want) != 0 {
		t.Fatalf("fallback reduction = %x, want %x", value, want)
	}
}

func TestWindowedScalarMultiplicationAgainstAffine(t *testing.T) {
	curve := CurveIdtc26gost341012256paramSetA()
	wantX := new(big.Int).Set(curve.X)
	wantY := new(big.Int).Set(curve.Y)
	for scalar := int64(1); scalar <= 32; scalar++ {
		gotX, gotY, err := curve.Exp(big.NewInt(scalar), curve.X, curve.Y)
		if err != nil {
			t.Fatalf("Exp(%d): %v", scalar, err)
		}
		if gotX.Cmp(wantX) != 0 || gotY.Cmp(wantY) != 0 {
			t.Fatalf("Exp(%d) disagrees with affine addition", scalar)
		}
		curve.add(wantX, wantY, curve.X, curve.Y)
	}
}
