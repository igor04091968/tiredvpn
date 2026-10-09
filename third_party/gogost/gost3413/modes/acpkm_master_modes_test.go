package modes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"testing"
)

func masterHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 8645 Appendix A.2.2 uses AES-256 to specify the mode independently of
// the block cipher. The same mode core is used by the public GOST constructors.
func TestACPKMMasterRFC8645AES(t *testing.T) {
	key := masterHex(t, "8899AABBCCDDEEFF0011223344556677FEDCBA98765432100123456789ABCDEF")
	iv := masterHex(t, "1234567890ABCEF0A1B2C3D4E5F00112")
	plain := masterHex(t, "1122334455667700FFEEDDCCBBAA9988"+
		"00112233445566778899AABBCCEEFF0A"+
		"112233445566778899AABBCCEEFF0A00"+
		"2233445566778899AABBCCEEFF0A0011"+
		"33445566778899AABBCCEEFF0A001122"+
		"445566778899AABBCCEEFF0A00112233"+
		"5566778899AABBCCEEFF0A0011223344")
	newAES := func(key []byte) (cipher.Block, error) { return aes.NewCipher(key) }
	newCore := func(extra, frequency int) *masterCore {
		c, err := newMasterCore(key, newAES, 32, frequency, extra)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	t.Run("CTR", func(t *testing.T) {
		m := &CTRACPKMMaster{core: newCore(0, 64)}
		copy(m.iv[:], iv[:8])
		want := masterHex(t, "9D8085C6F236123F7151D52B2433D4D4"+
			"F6B787891C41789AAB459BD31EDB76AB"+
			"5B256CC250E1051C8424C634DC0B2971"+
			"010622FA07AA763E1BD3F3544F584AC6"+
			"9B4D38DA9F33CB5665A2ED8FCB6684CA"+
			"82B608F9D31B007F6A82EB87B1E7B9DC"+
			"D74D9E8F0F9DFF599BC935A716DA7366")
		got := make([]byte, len(plain))
		if _, err := m.EncryptTo(got, plain); err != nil || !bytes.Equal(got, want) {
			t.Fatalf("RFC CTR: %x, %v", got, err)
		}
		for _, split := range []int{1, 15, 16, 31, 32, 33, 63, 64, 95, 111} {
			chunk := make([]byte, len(plain))
			if _, err := m.XORKeyStreamAt(chunk[:split], plain[:split], 0); err != nil {
				t.Fatal(err)
			}
			if _, err := m.XORKeyStreamAt(chunk[split:], plain[split:], split); err != nil || !bytes.Equal(chunk, want) {
				t.Fatalf("RFC CTR split %d: %x, %v", split, chunk, err)
			}
		}
		if _, err := m.DecryptTo(got, got); err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("RFC CTR decrypt: %x, %v", got, err)
		}
	})
	t.Run("CBC", func(t *testing.T) {
		m := &CBCACPKMMaster{core: newCore(0, 64)}
		copy(m.iv[:], iv)
		want := masterHex(t, "59CB5BCAC2692C600D4603A0C740C97C"+
			"80B60274548BF7C9781FA1058BF68B42"+
			"8C24FBCF6815B1AF65FE477595B49759"+
			"1965A500580D5023721BE990E18330E9"+
			"56D834F46F0F4DE62053A95CB5F63C14"+
			"66682B8BDD6EB27EDEC751D62F45A545"+
			"7F4D87F9CAE9560979C4FAFE340B4534")
		got := make([]byte, len(plain))
		if _, err := m.EncryptTo(got, plain); err != nil || !bytes.Equal(got, want) {
			t.Fatalf("RFC CBC: %x, %v", got, err)
		}
		if _, err := m.DecryptTo(got, got); err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("RFC CBC decrypt: %x, %v", got, err)
		}
	})
	t.Run("CFB", func(t *testing.T) {
		m := &CFBACPKMMaster{core: newCore(0, 64)}
		copy(m.iv[:], iv)
		want := masterHex(t, "0D1BAE1DAD3BE691563CCF53D8BF098B"+
			"6BB3E771163CA07C9D8DAC3C5CA80924"+
			"84676C9F96F87D9B0661AB395386A988"+
			"C2997608E6D3CF0C10F9738D0740C8A3"+
			"CD06D916B5D957B98D0D51BBF24977AB"+
			"4571E6F00E810FF8DDE433BF0AF42090"+
			"C23AE1BFCCB437B3")
		got := make([]byte, len(want))
		if _, err := m.EncryptTo(got, plain[:len(want)]); err != nil || !bytes.Equal(got, want) {
			t.Fatalf("RFC CFB: %x, %v", got, err)
		}
		if _, err := m.DecryptTo(got, got); err != nil || !bytes.Equal(got, plain[:len(want)]) {
			t.Fatalf("RFC CFB decrypt: %x, %v", got, err)
		}
	})
	t.Run("OMAC", func(t *testing.T) {
		m := &OMACACPKMMaster{core: newCore(16, 96), tagSize: 16}
		want := masterHex(t, "B3ADB8921832054C0921E7B808CFA0B8")
		got := m.Sum(nil, plain[:80])
		if !bytes.Equal(got, want) || !m.Verify(plain[:80], want) {
			t.Fatalf("RFC OMAC: %x", got)
		}
		// The RFC publishes the state C4, last section key and derived K2.
		// For a 79-byte prefix, form the padded last block independently.
		previous := masterHex(t, "B683E396FD30CD4679C18B2403821D81")
		lastKey := masterHex(t, "F2EE91456BDC3DE4912C87C329CF31A92F202E5AC49A2A653133D6748C4FF912")
		subkey := masterHex(t, "F0438F8ED97AF2C6AD59F11CD2D4000E")
		var final [16]byte
		copy(final[:], plain[64:79])
		final[15] = 0x80
		for i := range final {
			final[i] ^= previous[i] ^ subkey[i]
		}
		aesBlock, err := aes.NewCipher(lastKey)
		if err != nil {
			t.Fatal(err)
		}
		aesBlock.Encrypt(final[:], final[:])
		if got := m.Sum(nil, plain[:79]); !bytes.Equal(got, final[:]) {
			t.Fatalf("RFC OMAC partial: %x, want %x", got, final)
		}
		if m.Verify(plain[:79], want) || m.Verify(plain[:80], want[:15]) {
			t.Fatal("invalid OMAC accepted")
		}
	})
}

func TestACPKMMasterGOSTModes(t *testing.T) {
	key := bytes.Repeat([]byte{0x71}, 32)
	iv16 := bytes.Repeat([]byte{0x33}, 16)
	iv8 := iv16[:8]
	for _, tc := range []struct {
		name string
		make func() (*masterCore, error)
		ctr  func() (*CTRACPKMMaster, error)
		cbc  func() (*CBCACPKMMaster, error)
		cfb  func() (*CFBACPKMMaster, error)
		omac func() (*OMACACPKMMaster, error)
		bs   int
	}{
		{"Kuznechik", nil, func() (*CTRACPKMMaster, error) { return MustKuznechik(key).CTRACPKMMaster(iv8, 32, 64) },
			func() (*CBCACPKMMaster, error) { return MustKuznechik(key).CBCACPKMMaster(iv16, 32, 64) },
			func() (*CFBACPKMMaster, error) { return MustKuznechik(key).CFBACPKMMaster(iv16, 32, 64) },
			func() (*OMACACPKMMaster, error) { return MustKuznechik(key).OMACACPKMMaster(32, 96, 16) }, 16},
		{"Magma", nil, func() (*CTRACPKMMaster, error) { return MustMagma(key).CTRACPKMMaster(iv8[:4], 32, 64) },
			func() (*CBCACPKMMaster, error) { return MustMagma(key).CBCACPKMMaster(iv8, 32, 64) },
			func() (*CFBACPKMMaster, error) { return MustMagma(key).CFBACPKMMaster(iv8, 32, 64) },
			func() (*OMACACPKMMaster, error) { return MustMagma(key).OMACACPKMMaster(40, 80, 8) }, 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plain := bytes.Repeat([]byte{0x42}, 112)
			ctr, err := tc.ctr()
			if err != nil {
				t.Fatal(err)
			}
			ciphertext := make([]byte, len(plain))
			if _, err := ctr.EncryptTo(ciphertext, plain); err != nil {
				t.Fatal(err)
			}
			if appended, err := ctr.Encrypt(nil, plain); err != nil || !bytes.Equal(appended, ciphertext) {
				t.Fatalf("CTR append: %v", err)
			}
			if _, err := ctr.DecryptTo(ciphertext, ciphertext); err != nil || !bytes.Equal(ciphertext, plain) {
				t.Fatalf("CTR: %v", err)
			}
			cbc, err := tc.cbc()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := cbc.EncryptTo(ciphertext, plain); err != nil {
				t.Fatal(err)
			}
			if appended, err := cbc.Encrypt(nil, plain); err != nil || !bytes.Equal(appended, ciphertext) {
				t.Fatalf("CBC append: %v", err)
			}
			if _, err := cbc.DecryptTo(ciphertext, ciphertext); err != nil || !bytes.Equal(ciphertext, plain) {
				t.Fatalf("CBC: %v", err)
			}
			cfb, err := tc.cfb()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := cfb.EncryptTo(ciphertext[:109], plain[:109]); err != nil {
				t.Fatal(err)
			}
			if appended, err := cfb.Encrypt(nil, plain[:109]); err != nil || !bytes.Equal(appended, ciphertext[:109]) {
				t.Fatalf("CFB append: %v", err)
			}
			if _, err := cfb.DecryptTo(ciphertext[:109], ciphertext[:109]); err != nil || !bytes.Equal(ciphertext[:109], plain[:109]) {
				t.Fatalf("CFB: %v", err)
			}
			omac, err := tc.omac()
			if err != nil {
				t.Fatal(err)
			}
			tag := omac.Sum(nil, plain[:109])
			if !omac.Verify(plain[:109], tag) || omac.Verify(plain[:108], tag) {
				t.Fatal("OMAC verification")
			}
		})
	}
}
