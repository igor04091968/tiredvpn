package cms_test

import (
	"testing"

	"gitverse.ru/uzer_007/gogost/v3/gost3410"
)

func testRecipient(t testing.TB, seed byte) *gost3410.PrivateKey {
	t.Helper()
	curve := gost3410.CurveDefault()
	raw := make([]byte, curve.PointSize())
	for i := range raw {
		raw[i] = seed + byte(i+1)
	}
	key, err := gost3410.NewPrivateKey(curve, raw)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
