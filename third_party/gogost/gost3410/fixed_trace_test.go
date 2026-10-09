//go:build gostcttrace && !gostlegacycurve

package gost3410

import (
	"math/big"
	"testing"
)

func fixedTraceScalarSet(q *big.Int) []*big.Int {
	ones := new(big.Int).Sub(q, big.NewInt(1))
	alternating := new(big.Int)
	for bit := 0; bit < q.BitLen()-1; bit += 2 {
		alternating.SetBit(alternating, bit, 1)
	}
	return []*big.Int{big.NewInt(1), big.NewInt(2), alternating, ones}
}

func traceFixedArbitrary[L fixedLimbs](curve *fixedCurve[L], scalar, x, y *big.Int) fixedTraceSnapshot {
	point := curve.pointFromBig(x, y)
	resetFixedTrace()
	if curve.edwards {
		edPoint := curve.edwardsFromWeierstrass(point.x, point.y)
		_ = curve.edwardsMultiply(edPoint, curve.scalarFromBig(scalar))
	} else {
		_ = curve.multiply(point, curve.scalarFromBig(scalar))
	}
	return snapshotFixedTrace()
}

func traceFixedBase[L fixedLimbs](curve *fixedCurve[L], scalar *big.Int) fixedTraceSnapshot {
	curve.baseOnce.Do(curve.buildBaseTable)
	resetFixedTrace()
	if curve.edwards {
		_ = curve.multiplyBaseEdwards(curve.scalarFromBig(scalar))
	} else {
		_ = curve.multiplyBaseProjective(curve.scalarFromBig(scalar))
	}
	return snapshotFixedTrace()
}

func verifyFixedTrace[L fixedLimbs](t *testing.T, source *Curve, curve *fixedCurve[L]) {
	t.Helper()
	scalars := fixedTraceScalarSet(source.Q)
	wantArbitrary := traceFixedArbitrary(curve, scalars[0], source.X, source.Y)
	wantBase := traceFixedBase(curve, scalars[0])
	for _, scalar := range scalars[1:] {
		if got := traceFixedArbitrary(curve, scalar, source.X, source.Y); got != wantArbitrary {
			t.Fatalf("arbitrary scalar %x trace = %+v, want %+v", scalar, got, wantArbitrary)
		}
		if got := traceFixedBase(curve, scalar); got != wantBase {
			t.Fatalf("base scalar %x trace = %+v, want %+v", scalar, got, wantBase)
		}
	}
}

func TestFixedSecretScalarOperationTrace(t *testing.T) {
	for _, tc := range builtinCurveTests() {
		t.Run(tc.name, func(t *testing.T) {
			curve := tc.new()
			if curve.P.BitLen() <= 256 {
				verifyFixedTrace(t, curve, curve.fixedState.get256(curve))
				return
			}
			verifyFixedTrace(t, curve, curve.fixedState.get512(curve))
		})
	}
}
