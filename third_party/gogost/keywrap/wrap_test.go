package keywrap_test

import (
	"bytes"
	"errors"
	"testing"

	"gitverse.ru/uzer_007/gogost/v3/keywrap"
)

func seq(n int, start byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = start + byte(i*17)
	}
	return out
}

func TestWrapRoundTrip(t *testing.T) {
	kek := seq(keywrap.CEKSize, 1)
	cek := seq(keywrap.CEKSize, 7)
	ukm := seq(keywrap.UKMSize, 3)

	for _, tc := range []struct {
		name string
		alg  keywrap.Algorithm
	}{
		{"gost28147", keywrap.AlgorithmGost28147},
		{"cryptopro", keywrap.AlgorithmCryptoPro},
		{"magma", keywrap.AlgorithmMagma},
		{"kuznechik", keywrap.AlgorithmKuznechik},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wrapped, err := keywrap.Wrap(nil, cek, keywrap.Config{
				Algorithm: tc.alg,
				KEK:       kek,
				UKM:       ukm,
			})
			if err != nil {
				t.Fatal(err)
			}
			got, err := keywrap.Unwrap(nil, wrapped, keywrap.Config{
				Algorithm: tc.alg,
				KEK:       kek,
			})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, cek) {
				t.Fatalf("CEK mismatch: %x != %x", got, cek)
			}
		})
	}
}

func TestWrapTamper(t *testing.T) {
	kek := seq(keywrap.CEKSize, 1)
	cek := seq(keywrap.CEKSize, 7)
	ukm := seq(keywrap.UKMSize, 3)

	for _, alg := range []keywrap.Algorithm{
		keywrap.AlgorithmGost28147,
		keywrap.AlgorithmCryptoPro,
		keywrap.AlgorithmMagma,
		keywrap.AlgorithmKuznechik,
	} {
		wrapped, err := keywrap.Wrap(nil, cek, keywrap.Config{Algorithm: alg, KEK: kek, UKM: ukm})
		if err != nil {
			t.Fatal(err)
		}
		wrapped[len(wrapped)-1] ^= 0xff
		_, err = keywrap.Unwrap(nil, wrapped, keywrap.Config{Algorithm: alg, KEK: kek})
		if !errors.Is(err, keywrap.ErrInvalidMAC) {
			t.Fatalf("%v unwrap error=%v, want ErrInvalidMAC", alg, err)
		}
	}
}

func TestWrapInvalidInputs(t *testing.T) {
	_, err := keywrap.Wrap(nil, seq(keywrap.CEKSize, 1), keywrap.Config{
		Algorithm: keywrap.AlgorithmMagma,
		KEK:       seq(keywrap.CEKSize-1, 2),
		UKM:       seq(keywrap.UKMSize, 3),
	})
	if !errors.Is(err, keywrap.ErrInvalidKEKSize) {
		t.Fatalf("KEK error=%v", err)
	}

	_, err = keywrap.Wrap(nil, seq(keywrap.CEKSize-1, 1), keywrap.Config{
		Algorithm: keywrap.AlgorithmMagma,
		KEK:       seq(keywrap.CEKSize, 2),
		UKM:       seq(keywrap.UKMSize, 3),
	})
	if !errors.Is(err, keywrap.ErrInvalidCEKSize) {
		t.Fatalf("CEK error=%v", err)
	}

	_, err = keywrap.Wrap(nil, seq(keywrap.CEKSize, 1), keywrap.Config{
		Algorithm: keywrap.AlgorithmMagma,
		KEK:       seq(keywrap.CEKSize, 2),
		UKM:       seq(keywrap.UKMSize-1, 3),
	})
	if !errors.Is(err, keywrap.ErrInvalidUKMSize) {
		t.Fatalf("UKM error=%v", err)
	}

	_, err = keywrap.Unwrap(nil, []byte{1, 2, 3}, keywrap.Config{
		Algorithm: keywrap.AlgorithmMagma,
		KEK:       seq(keywrap.CEKSize, 2),
	})
	if !errors.Is(err, keywrap.ErrInvalidWrappedKeySize) {
		t.Fatalf("wrapped error=%v", err)
	}
}
