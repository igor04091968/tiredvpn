package cms

import (
	"encoding/asn1"
	"math/rand"
	"testing"
)

func TestParseOIDMatchesStandardDecoder(t *testing.T) {
	for _, want := range []asn1.ObjectIdentifier{
		{0, 0}, {0, 39}, {1, 0}, {1, 39}, {2, 0}, {2, 999, 3},
		{1, 2, 840, 113549, 1, 7, 2}, {2, 2147483567, 2147483647},
	} {
		der, err := asn1.Marshal(want)
		if err != nil {
			t.Fatal(err)
		}
		got, rest, err := parseOID(der)
		if err != nil || len(rest) != 0 || !got.Equal(want) {
			t.Fatalf("%v: got %v, rest %x, error %v", want, got, rest, err)
		}
	}

	// Include malformed, nonminimal, truncated and oversized base-128 values.
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 10000; i++ {
		n := 1 + rng.Intn(12)
		der := make([]byte, n+2)
		der[0], der[1] = 0x06, byte(n)
		_, _ = rng.Read(der[2:])
		var want asn1.ObjectIdentifier
		_, standardErr := asn1.Unmarshal(der, &want)
		got, rest, err := parseOID(der)
		if (err == nil) != (standardErr == nil) || err == nil && (len(rest) != 0 || !got.Equal(want)) {
			t.Fatalf("%x: got %v, error %v; standard %v, error %v", der, got, err, want, standardErr)
		}
	}
}
