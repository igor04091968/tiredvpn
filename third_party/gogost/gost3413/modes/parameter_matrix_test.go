package modes_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"gitverse.ru/uzer_007/gogost/v3/gost3412128"
	"gitverse.ru/uzer_007/gogost/v3/gost3413/modes"
)

func decodeMatrixHex(t *testing.T, s string) []byte {
	t.Helper()
	v, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// GOST R 34.13-2015 Appendix A.1.4 and A.2.4 exercise CBC with m=2n/3n.
func TestCBCExtendedRegisterOfficialVectors(t *testing.T) {
	for _, tc := range []struct {
		name, key, iv, plaintext, ciphertext string
		newCipher                            func([]byte) (interface {
			CBC([]byte, modes.Padding) (*modes.CBC, error)
		}, error)
	}{
		{
			name:       "Kuznechik-m2n",
			key:        "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
			iv:         "1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819",
			plaintext:  "1122334455667700ffeeddccbbaa9988" + "00112233445566778899aabbcceeff0a" + "112233445566778899aabbcceeff0a00" + "2233445566778899aabbcceeff0a0011",
			ciphertext: "689972d4a085fa4d90e52e3d6d7dcc27" + "2826e661b478eca6af1e8e448d5ea5ac" + "fe7babf1e91999e85640e8b0f49d90d0" + "167688065a895c631a2d9a1560b63970",
			newCipher: func(key []byte) (interface {
				CBC([]byte, modes.Padding) (*modes.CBC, error)
			}, error) {
				k, err := modes.NewKuznechik(key)
				return k, err
			},
		},
		{
			name:       "Magma-m3n",
			key:        "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
			iv:         "1234567890abcdef234567890abcdef134567890abcdef12",
			plaintext:  "92def06b3c130a59" + "db54c704f8189d20" + "4a98fb2e67a8024c" + "8912409b17b57e41",
			ciphertext: "96d1b05eea683919" + "aff76129abb937b9" + "5058b4a1c4bc0019" + "20b78b1a7cd7e667",
			newCipher: func(key []byte) (interface {
				CBC([]byte, modes.Padding) (*modes.CBC, error)
			}, error) {
				m, err := modes.NewMagma(key)
				return m, err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine, err := tc.newCipher(decodeMatrixHex(t, tc.key))
			if err != nil {
				t.Fatal(err)
			}
			mode, err := engine.CBC(decodeMatrixHex(t, tc.iv), modes.PaddingNone)
			if err != nil {
				t.Fatal(err)
			}
			plain := decodeMatrixHex(t, tc.plaintext)
			want := decodeMatrixHex(t, tc.ciphertext)
			got := make([]byte, len(plain))
			if _, err := mode.EncryptTo(got, plain); err != nil || !bytes.Equal(got, want) {
				t.Fatalf("encrypt: %x, %v", got, err)
			}
			if _, err := mode.DecryptTo(got, got); err != nil || !bytes.Equal(got, plain) {
				t.Fatalf("decrypt: %x, %v", got, err)
			}
		})
	}
}

// The appendix only publishes s=n vectors. This checks the byte-granular
// CTR parameter against an independently constructed AES block oracle.
func TestCTRSegmentMatrix(t *testing.T) {
	key := decodeMatrixHex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	engine := modes.MustKuznechik(key)
	iv := decodeMatrixHex(t, "1234567890abcef0")
	plain := bytes.Repeat([]byte{0x5c}, 97)
	block := gost3412128.NewCipher(key)
	for _, s := range []int{1, 3, 8, 15, 16} {
		t.Run(fmt.Sprintf("s=%d", s), func(t *testing.T) {
			mode, err := engine.CTRN(iv, s)
			if err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(plain))
			if _, err := mode.EncryptTo(got, plain); err != nil {
				t.Fatal(err)
			}
			counter := make([]byte, 16)
			copy(counter, iv)
			gamma := make([]byte, 16)
			want := make([]byte, len(plain))
			for pos := 0; pos < len(plain); pos += s {
				block.Encrypt(gamma, counter)
				for i := 0; i < s && pos+i < len(plain); i++ {
					want[pos+i] = plain[pos+i] ^ gamma[i]
				}
				for j := len(counter) - 1; j >= 0; j-- {
					counter[j]++
					if counter[j] != 0 {
						break
					}
				}
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("segment mismatch: %x", got)
			}
			if _, err := mode.DecryptTo(got, got); err != nil || !bytes.Equal(got, plain) {
				t.Fatalf("round trip: %v", err)
			}
		})
	}
	standardPlain := decodeMatrixHex(t, "1122334455667700ffeeddccbbaa9988"+
		"00112233445566778899aabbcceeff0a"+
		"112233445566778899aabbcceeff0a00"+
		"2233445566778899aabbcceeff0a0011")
	standardCipher := decodeMatrixHex(t, "f195d8bec10ed1dbd57b5fa240bda1b8"+
		"85eee733f6a13e5df33ce4b33c45dee4"+
		"a5eae88be6356ed3d5e877f13564a3a5"+
		"cb91fab1f20cbab6d1c6d15820bdba73")
	full, err := engine.CTRN(iv, 16)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(standardPlain))
	if _, err := full.EncryptTo(got, standardPlain); err != nil || !bytes.Equal(got, standardCipher) {
		t.Fatalf("official CTR vector: %x, %v", got, err)
	}
	if _, err := engine.CTRN(iv, 0); !errors.Is(err, modes.ErrInvalidInput) {
		t.Fatalf("zero segment: %v", err)
	}
	if _, err := engine.CTRN(iv, 17); !errors.Is(err, modes.ErrInvalidInput) {
		t.Fatalf("large segment: %v", err)
	}
	if _, err := engine.CTRN(iv[:7], 8); !errors.Is(err, modes.ErrInvalidIVSize) {
		t.Fatalf("nonce length: %v", err)
	}
	if _, err := engine.CBC(iv[:7], modes.PaddingNone); !errors.Is(err, modes.ErrInvalidIVSize) {
		t.Fatalf("CBC IV length: %v", err)
	}
	if _, err := engine.OFBN(make([]byte, 24), 8, 24); !errors.Is(err, modes.ErrInvalidInput) {
		t.Fatalf("OFB register granularity: %v", err)
	}
}
