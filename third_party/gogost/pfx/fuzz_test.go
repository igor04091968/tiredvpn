package pfx

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"testing"

	"gitverse.ru/uzer_007/gogost/v3/gost3410"
	"gitverse.ru/uzer_007/gogost/v3/gostx509"
)

func FuzzPFXParsers(f *testing.F) {
	read := func(path string) []byte {
		encoded, err := os.ReadFile(path)
		if err != nil {
			f.Fatal(err)
		}
		der, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(encoded)))
		if err != nil {
			f.Fatal(err)
		}
		return der
	}
	cert, err := gostx509.ParseCertificate(read("testdata/r1323565_1_041_2022_a4_recipient.b64"))
	if err != nil {
		f.Fatal(err)
	}
	pub := cert.PublicKey.(*gost3410.PublicKey)
	raw, _ := hex.DecodeString("0DC8DC1FF2BC114BABC3F1CA8C51E4F58610427E197B1C2FBDBA4AE58CBFB7CE")
	key, err := gost3410.NewPrivateKeyBE(pub.C, raw)
	if err != nil {
		f.Fatal(err)
	}
	if matchKeyCertificate(key, cert) != nil {
		key, err = gost3410.NewPrivateKeyLE(pub.C, raw)
		if err != nil || matchKeyCertificate(key, cert) != nil {
			f.Fatal("standard recipient key mismatch")
		}
	}
	f.Add(read("testdata/r1323565_1_041_2022_a4.b64"))
	f.Add([]byte{0x30, 0x00})
	f.Fuzz(func(t *testing.T, der []byte) {
		_, _ = ParseForRecipient(der, cert, key)
		_, _, _, _ = ParsePassword(der, "test")
	})
}
