package gosttls

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"testing"
)

func deterministicBytes(length, multiplier int) []byte {
	out := make([]byte, length)
	for i := range out {
		out[i] = byte(i*multiplier + 7)
	}
	return out
}

func TestGOSTHKDFDifferential(t *testing.T) {
	for _, tc := range []struct {
		secret, salt []byte
	}{
		{nil, nil},
		{[]byte{}, []byte{}},
		{deterministicBytes(32, 3), deterministicBytes(32, 5)},
		{deterministicBytes(97, 7), deterministicBytes(81, 11)},
	} {
		want, err := hkdf.Extract(hashGOST256.New, tc.secret, tc.salt)
		if err != nil {
			t.Fatal(err)
		}
		got := gostHKDFExtract(tc.secret, tc.salt)
		if !bytes.Equal(got, want) {
			t.Fatal("specialized HKDF-Extract differs from crypto/hkdf")
		}
		for _, length := range []int{0, 1, 31, 32, 33, 64, 257, 255 * gostHKDFHashSize} {
			info := deterministicBytes(73, 13)
			want, err := hkdf.Expand(hashGOST256.New, got, string(info), length)
			if err != nil {
				t.Fatal(err)
			}
			if actual := gostHKDFExpand(got, info, length); !bytes.Equal(actual, want) {
				t.Fatalf("specialized HKDF-Expand differs at length %d", length)
			}
		}
	}
}

func TestGOSTExpandLabelDifferential(t *testing.T) {
	secret := deterministicBytes(32, 17)
	contexts := [][]byte{nil, {}, deterministicBytes(32, 19), deterministicBytes(255, 23)}
	labels := []string{"", "key", "traffic upd", string(deterministicBytes(249, 29))}
	for _, context := range contexts {
		for _, label := range labels {
			for _, length := range []int{0, 1, 32, 33, 512} {
				want := expandLabelTLS13(hashGOST256.New, secret, label, context, length)
				got := gostExpandLabel(secret, label, context, length)
				if !bytes.Equal(got, want) {
					t.Fatalf("label=%d context=%d length=%d differs", len(label), len(context), length)
				}
			}
		}
	}
}

func TestGOSTFinishedHashDifferential(t *testing.T) {
	baseKey := deterministicBytes(32, 31)
	transcript := deterministicBytes(32, 37)
	finishedKey := expandLabelTLS13(hashGOST256.New, baseKey, "finished", nil, 32)
	wantHMAC := hmac.New(hashGOST256.New, finishedKey)
	_, _ = wantHMAC.Write(transcript)
	want := wantHMAC.Sum(nil)
	if got := gostFinishedHash(baseKey, transcript); !bytes.Equal(got, want) {
		t.Fatal("specialized Finished HMAC differs")
	}
}

func TestGOSTTrafficSecretReusesAEAD(t *testing.T) {
	suite := cipherSuiteTLS13ByID(TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L)
	var half halfConn
	firstSecret := deterministicBytes(32, 41)
	secondSecret := deterministicBytes(32, 43)
	half.setTrafficSecret(suite, firstSecret)
	first, ok := half.cipher.(*gostAEAD)
	if !ok {
		t.Fatal("GOST suite did not create gostAEAD")
	}
	half.setTrafficSecret(suite, secondSecret)
	second, ok := half.cipher.(*gostAEAD)
	if !ok || first != second {
		t.Fatal("traffic-secret transition replaced rather than reset gostAEAD")
	}
	if !bytes.Equal(firstSecret, make([]byte, len(firstSecret))) {
		t.Fatal("previous traffic secret was not cleared")
	}
}
