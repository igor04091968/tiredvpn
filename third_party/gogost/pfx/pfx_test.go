package pfx

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"os"
	"testing"

	"gitverse.ru/uzer_007/gogost/v3/gost3410"
	"gitverse.ru/uzer_007/gogost/v3/gostx509"
	"gitverse.ru/uzer_007/gogost/v3/keywrap"
)

func readStandardBase64(t *testing.T, path string) []byte {
	t.Helper()
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	der, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func standardRecipient(t *testing.T) (*gostx509.Certificate, *gost3410.PrivateKey) {
	t.Helper()
	cert, err := gostx509.ParseCertificate(readStandardBase64(t, "testdata/r1323565_1_041_2022_a4_recipient.b64"))
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := cert.PublicKey.(*gost3410.PublicKey)
	if !ok {
		t.Fatal("recipient certificate is not GOST")
	}
	// The trailing 16 in the printed standard is a base subscript.
	raw, err := hex.DecodeString("0DC8DC1FF2BC114BABC3F1CA8C51E4F58610427E197B1C2FBDBA4AE58CBFB7CE")
	if err != nil {
		t.Fatal(err)
	}
	for _, constructor := range []func(*gost3410.Curve, []byte) (*gost3410.PrivateKey, error){gost3410.NewPrivateKeyLE, gost3410.NewPrivateKeyBE} {
		key, err := constructor(pub.C, raw)
		if err == nil && matchKeyCertificate(key, cert) == nil {
			return cert, key
		}
	}
	t.Fatal("standard recipient private key does not match certificate")
	return nil, nil
}

func TestR1323565_1_041_2022AppendixA4(t *testing.T) {
	cert, key := standardRecipient(t)
	der := readStandardBase64(t, "testdata/r1323565_1_041_2022_a4.b64")
	container, err := ParseForRecipient(der, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if container.Key == nil || container.Certificate == nil || len(container.Signers) == 0 {
		t.Fatal("missing key, certificate or verified sender")
	}
	if matchKeyCertificate(container.Key, container.Certificate) != nil {
		t.Fatal("transported key does not match its certificate")
	}
	der[len(der)-1] ^= 1
	if _, err := ParseForRecipient(der, cert, key); err == nil {
		t.Fatal("modified standard signature accepted")
	}
}

func TestPublicKeyPFXRoundTrip(t *testing.T) {
	cert, key := standardRecipient(t)
	for _, algorithm := range []keywrap.Algorithm{keywrap.AlgorithmKuznechik, keywrap.AlgorithmMagma, keywrap.AlgorithmCryptoPro} {
		t.Run(string(rune('0'+algorithm)), func(t *testing.T) {
			der, err := MarshalForRecipients(key, cert, nil, RecipientProtection{
				Recipients: []*gostx509.Certificate{cert}, SignerCertificate: cert,
				Signer: key, Algorithm: algorithm,
			})
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseForRecipient(der, cert, key)
			if err != nil {
				t.Fatal(err)
			}
			if matchKeyCertificate(parsed.Key, cert) != nil || !bytes.Equal(parsed.Certificate.Raw, cert.Raw) || len(parsed.Signers) != 1 {
				t.Fatal("transported identity mismatch")
			}
			wrong, err := gost3410.GenPrivateKey(key.C, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseForRecipient(der, cert, wrong); err == nil {
				t.Fatal("wrong recipient key accepted")
			}
			der[len(der)-1] ^= 1
			if _, err := ParseForRecipient(der, cert, key); err == nil {
				t.Fatal("modified signature accepted")
			}
		})
	}
}

func TestCompetitorPublicKeyPFX(t *testing.T) {
	cert, key := standardRecipient(t)
	der, err := os.ReadFile("testdata/competitor-interop/public.p12")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseForRecipient(der, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if matchKeyCertificate(parsed.Key, cert) != nil || !bytes.Equal(parsed.Certificate.Raw, cert.Raw) || len(parsed.Signers) != 1 {
		t.Fatal("competitor PFX transported identity mismatch")
	}
	wrong, err := gost3410.GenPrivateKey(key.C, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseForRecipient(der, cert, wrong); err == nil {
		t.Fatal("wrong recipient key accepted")
	}
	modified := append([]byte(nil), der...)
	modified[len(modified)-1] ^= 1
	if _, err := ParseForRecipient(modified, cert, key); err == nil {
		t.Fatal("modified competitor PFX accepted")
	}
}

func TestPublicPFXLegacyParamSetValidation(t *testing.T) {
	cert, key := standardRecipient(t)
	base := RecipientProtection{
		Recipients: []*gostx509.Certificate{cert}, SignerCertificate: cert,
		Signer: key, Algorithm: keywrap.AlgorithmCryptoPro,
	}
	base.LegacyParamSet = 255
	if _, err := MarshalForRecipients(key, cert, nil, base); err == nil {
		t.Fatal("unsupported legacy parameter set accepted")
	}
	base.Algorithm = keywrap.AlgorithmKuznechik
	if _, err := MarshalForRecipients(key, cert, nil, base); err == nil {
		t.Fatal("irrelevant legacy parameter set accepted for modern profile")
	}
}
