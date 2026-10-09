package cms_test

import (
	"bytes"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"io"
	"math/big"
	"testing"
	"time"

	"gitverse.ru/uzer_007/gogost/v3/cms"
	"gitverse.ru/uzer_007/gogost/v3/gost3410"
	"gitverse.ru/uzer_007/gogost/v3/gostx509"
)

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) / 2, nil }

func cms2001Identity(t testing.TB, serial int64) (*gostx509.Certificate, *gost3410.PrivateKey) {
	t.Helper()
	key, err := gost3410.GenPrivateKey(gost3410.CurveIdGostR34102001CryptoProAParamSet(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	template := &gostx509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "CMS recipient"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: gostx509.KeyUsageKeyAgreement | gostx509.KeyUsageCertSign,
		IsCA:     true, BasicConstraintsValid: true,
	}
	der, err := gostx509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := gostx509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestEnvelopedDataMultipleRecipients(t *testing.T) {
	first, firstKey := cms2001Identity(t, 100)
	second, secondKey := cms2001Identity(t, 101)
	content := []byte("classic CMS has no authenticated content")
	der, err := cms.EncryptEnveloped(content, []*gostx509.Certificate{first, second})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := cms.ParseEnvelopedData(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(envelope.Recipients) != 2 {
		t.Fatalf("recipients=%d", len(envelope.Recipients))
	}
	if err := envelope.DecryptUnauthenticatedTo(shortWriter{}, first, firstKey); err != io.ErrShortWrite {
		t.Fatalf("short write: %v", err)
	}
	for _, recipient := range []struct {
		cert *gostx509.Certificate
		key  *gost3410.PrivateKey
	}{{first, firstKey}, {second, secondKey}} {
		var out bytes.Buffer
		if err := envelope.DecryptUnauthenticatedTo(&out, recipient.cert, recipient.key); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out.Bytes(), content) {
			t.Fatal("plaintext mismatch")
		}
	}
	third, thirdKey := cms2001Identity(t, 102)
	if _, err := envelope.DecryptUnauthenticated(third, thirdKey); err == nil {
		t.Fatal("unlisted recipient accepted")
	}
	corrupt := append([]byte(nil), der...)
	corrupt[len(corrupt)-1] ^= 1
	parsed, err := cms.ParseEnvelopedData(corrupt)
	if err != nil {
		t.Fatal(err)
	}
	// EnvelopedData has no content authentication; ciphertext corruption is
	// deliberately detectable only by an independent signature.
	if _, err := parsed.DecryptUnauthenticated(first, firstKey); err != nil {
		t.Fatal(err)
	}
}

func TestEnvelopedDataStreamingBER(t *testing.T) {
	cert, key := cms2001Identity(t, 150)
	content := bytes.Repeat([]byte("streaming CMS content;"), 60000)
	var encoded bytes.Buffer
	if err := cms.EncryptEnvelopedTo(&encoded, bytes.NewReader(content), []*gostx509.Certificate{cert}); err != nil {
		t.Fatal(err)
	}
	envelope, err := cms.ParseEnvelopedData(encoded.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	var plaintext bytes.Buffer
	if err := envelope.DecryptUnauthenticatedTo(&plaintext, cert, key); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext.Bytes(), content) {
		t.Fatal("streamed plaintext mismatch")
	}
	if err := cms.EncryptEnvelopedTo(shortWriter{}, bytes.NewReader(content), []*gostx509.Certificate{cert}); err != io.ErrShortWrite {
		t.Fatalf("short writer: %v", err)
	}
}

func rfc4491Certificate(t *testing.T) *gostx509.Certificate {
	t.Helper()
	// RFC 4491 section 4.2.
	const certificateBase64 = "MIIB0DCCAX8CECv1xh7CEb0Xx9zUYma0LiEwCAYGKoUDAgIDMG0xHzAdBgNVBAMM" +
		"Fkdvc3RSMzQxMC0yMDAxIGV4YW1wbGUxEjAQBgNVBAoMCUNyeXB0b1BybzELMAkG" +
		"A1UEBhMCUlUxKTAnBgkqhkiG9w0BCQEWGkdvc3RSMzQxMC0yMDAxQGV4YW1wbGUu" +
		"Y29tMB4XDTA1MDgxNjE0MTgyMFoXDTE1MDgxNjE0MTgyMFowbTEfMB0GA1UEAwwW" +
		"R29zdFIzNDEwLTIwMDEgZXhhbXBsZTESMBAGA1UECgwJQ3J5cHRvUHJvMQswCQYD" +
		"VQQGEwJSVTEpMCcGCSqGSIb3DQEJARYaR29zdFIzNDEwLTIwMDFAZXhhbXBsZS5j" +
		"b20wYzAcBgYqhQMCAhMwEgYHKoUDAgIkAAYHKoUDAgIeAQNDAARAhJVodWACGkB1" +
		"CM0TjDGJLP3lBQN6Q1z0bSsP508yfleP68wWuZWIA9CafIWuD+SN6qa7flbHy7Df" +
		"D2a8yuoaYDAIBgYqhQMCAgMDQQA8L8kJRLcnqeyn1en7U23Sw6pkfEQu3u0xFkVP" +
		"vFQ/3cHeF26NG+xxtZPz3TaTVXdoiYkXYiD02rEx1bUcM97i"
	certDER, err := base64.StdEncoding.DecodeString(certificateBase64)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := gostx509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestRFC4490KeyTransportEnvelopeParses(t *testing.T) {
	// RFC 4490 section 9.3: independently encoded GOST R 34.10-2001 CMS.
	const encoded = "MIIBpwYJKoZIhvcNAQcDoIIBmDCCAZQCAQAxggFTMIIBTwIBADCBgTBtMR8wHQYD" +
		"VQQDDBZHb3N0UjM0MTAtMjAwMSBleGFtcGxlMRIwEAYDVQQKDAlDcnlwdG9Qcm8x" +
		"CzAJBgNVBAYTAlJVMSkwJwYJKoZIhvcNAQkBFhpHb3N0UjM0MTAtMjAwMUBleGFt" +
		"cGxlLmNvbQIQK/XGHsIRvRfH3NRiZrQuITAcBgYqhQMCAhMwEgYHKoUDAgIkAAYH" +
		"KoUDAgIeAQSBpzCBpDAoBCBqL6ghBpVon5/kR6qey2EVK35BYLxdjfv1PSgbGJr5" +
		"dQQENm2Yt6B4BgcqhQMCAh8BoGMwHAYGKoUDAgITMBIGByqFAwICJAAGByqFAwIC" +
		"HgEDQwAEQE0rLzOQ5tyj3VUqzd/g7/sx93N+Tv+/eImKK8PNMZQESw5gSJYf28dd" +
		"Em/askCKd7W96vLsNMsjn5uL3Z4SwPYECJeV4ywrrSsMMDgGCSqGSIb3DQEHATAd" +
		"BgYqhQMCAhUwEwQIvBCLHwv/NCkGByqFAwICHwGADKqOch3uT7Mu4w+hNw=="
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := cms.ParseEnvelopedData(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(envelope.Recipients) != 1 || len(envelope.Ciphertext) != 12 {
		t.Fatalf("unexpected RFC envelope: recipients=%d ciphertext=%d", len(envelope.Recipients), len(envelope.Ciphertext))
	}
	cert := rfc4491Certificate(t)
	scalar, err := hex.DecodeString("0B293BE050D0082BDAE785631A6BAB68F35B42786D6DDA56AFAF169891040F77")
	if err != nil {
		t.Fatal(err)
	}
	private, err := gost3410.NewPrivateKeyBE(gost3410.CurveIdGostR34102001CryptoProXchAParamSet(), scalar)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := envelope.DecryptUnauthenticated(cert, private)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "sample text\n" {
		t.Fatalf("RFC 4490 plaintext = %x", plaintext)
	}
}
