package cms_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"gitverse.ru/uzer_007/gogost/v3/cms"
	"gitverse.ru/uzer_007/gogost/v3/gost3410"
	"gitverse.ru/uzer_007/gogost/v3/gostx509"
	"gitverse.ru/uzer_007/gogost/v3/keywrap"
)

func modernRecipientFixture(t testing.TB) (*gostx509.Certificate, []byte) {
	t.Helper()
	dir := filepath.Join("testdata", "openssl-modern-envelope")
	der, err := os.ReadFile(filepath.Join(dir, "recipient.der"))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := gostx509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(dir, "modern-content.txt"))
	if err != nil {
		t.Fatal(err)
	}
	return cert, content
}

func TestOpenSSLModernEnvelopedData(t *testing.T) {
	cert, content := modernRecipientFixture(t)
	key := testRecipient(t, 55)
	der, err := os.ReadFile(filepath.Join("testdata", "openssl-modern-envelope", "modern-envelope.der"))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := cms.ParseEnvelopedData(der)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := envelope.DecryptUnauthenticated(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, content) {
		t.Fatalf("OpenSSL plaintext: %q", plain)
	}
	corrupt := append([]byte(nil), der...)
	index := bytes.Index(corrupt, envelope.Recipients[0].UKM)
	if index < 0 {
		t.Fatal("transport UKM absent")
	}
	corrupt[index] ^= 1
	changed, err := cms.ParseEnvelopedData(corrupt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := changed.DecryptUnauthenticated(cert, key); err == nil {
		t.Fatal("corrupted key transport accepted")
	}
}

func TestOpenSSLModernMagmaAnd512(t *testing.T) {
	cert, content := modernRecipientFixture(t)
	key := testRecipient(t, 55)
	dir := filepath.Join("testdata", "openssl-modern-envelope")
	cert512DER, err := os.ReadFile(filepath.Join(dir, "recipient512.der"))
	if err != nil {
		t.Fatal(err)
	}
	cert512, err := gostx509.ParseCertificate(cert512DER)
	if err != nil {
		t.Fatal(err)
	}
	curve := gost3410.CurveIdtc26gost341012512paramSetA()
	raw := make([]byte, curve.PointSize())
	for i := range raw {
		raw[i] = 56 + byte(i+1)
	}
	key512, err := gost3410.NewPrivateKey(curve, raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct {
		name      string
		cert      *gostx509.Certificate
		key       *gost3410.PrivateKey
		algorithm keywrap.Algorithm
	}{
		{"modern-envelope-magma.der", cert, key, keywrap.AlgorithmMagma},
		{"modern-envelope-512.der", cert512, key512, keywrap.AlgorithmKuznechik},
	} {
		der, err := os.ReadFile(filepath.Join(dir, fixture.name))
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := cms.ParseEnvelopedData(der)
		if err != nil {
			t.Fatalf("%s: %v", fixture.name, err)
		}
		plain, err := envelope.DecryptUnauthenticated(fixture.cert, fixture.key)
		if err != nil {
			t.Fatalf("%s: %v", fixture.name, err)
		}
		if !bytes.Equal(plain, content) {
			t.Fatalf("%s: wrong plaintext %q; want %q", fixture.name, plain, content)
		}
		ours, err := cms.EncryptEnveloped2012(content, []*gostx509.Certificate{fixture.cert}, fixture.algorithm)
		if err != nil {
			t.Fatalf("%s: encrypt: %v", fixture.name, err)
		}
		parsed, err := cms.ParseEnvelopedData(ours)
		if err != nil {
			t.Fatal(err)
		}
		plain, err = parsed.DecryptUnauthenticated(fixture.cert, fixture.key)
		if err != nil || !bytes.Equal(plain, content) {
			t.Fatalf("%s: round trip: %v", fixture.name, err)
		}
	}
	mixedDER, err := cms.EncryptEnveloped2012(content, []*gostx509.Certificate{cert, cert512}, keywrap.AlgorithmKuznechik)
	if err != nil {
		t.Fatal(err)
	}
	mixed, err := cms.ParseEnvelopedData(mixedDER)
	if err != nil || len(mixed.Recipients) != 2 {
		t.Fatalf("mixed recipients: %v", err)
	}
	for _, identity := range []struct {
		cert *gostx509.Certificate
		key  *gost3410.PrivateKey
	}{{cert, key}, {cert512, key512}} {
		plain, err := mixed.DecryptUnauthenticated(identity.cert, identity.key)
		if err != nil || !bytes.Equal(plain, content) {
			t.Fatalf("mixed recipient decryption: %v", err)
		}
	}
}

func TestLegacy28147GOST2012MixedRecipients(t *testing.T) {
	cert256, _ := modernRecipientFixture(t)
	key256 := testRecipient(t, 55)
	cert512DER, err := os.ReadFile(filepath.Join("testdata", "openssl-modern-envelope", "recipient512.der"))
	if err != nil {
		t.Fatal(err)
	}
	cert512, err := gostx509.ParseCertificate(cert512DER)
	if err != nil {
		t.Fatal(err)
	}
	curve := gost3410.CurveIdtc26gost341012512paramSetA()
	raw := make([]byte, curve.PointSize())
	for i := range raw {
		raw[i] = 56 + byte(i+1)
	}
	key512, err := gost3410.NewPrivateKey(curve, raw)
	if err != nil {
		t.Fatal(err)
	}
	content := bytes.Repeat([]byte("CryptoPro meshing across sections."), 100)
	if _, err := cms.EncryptEnvelopedLegacyWithParamSet(content, []*gostx509.Certificate{cert256}, 255); err == nil {
		t.Fatal("unsupported GOST 28147 parameter set accepted")
	}
	der, err := cms.EncryptEnvelopedLegacy(content, []*gostx509.Certificate{cert256, cert512})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := cms.ParseEnvelopedData(der)
	if err != nil || len(envelope.Recipients) != 2 {
		t.Fatalf("legacy recipients: %v", err)
	}
	for _, recipient := range []struct {
		cert *gostx509.Certificate
		key  *gost3410.PrivateKey
	}{{cert256, key256}, {cert512, key512}} {
		plain, err := envelope.DecryptUnauthenticated(recipient.cert, recipient.key)
		if err != nil || !bytes.Equal(plain, content) {
			t.Fatalf("legacy decryption: %v", err)
		}
	}
}

func TestModernEnvelopedRoundTrip(t *testing.T) {
	cert, _ := modernRecipientFixture(t)
	key := testRecipient(t, 55)
	for _, algorithm := range []keywrap.Algorithm{keywrap.AlgorithmKuznechik, keywrap.AlgorithmMagma} {
		content := bytes.Repeat([]byte("GOST 2012 CMS section test;"), 10000)
		der, err := cms.EncryptEnveloped2012(content, []*gostx509.Certificate{cert}, algorithm)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := cms.ParseEnvelopedData(der)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := envelope.DecryptUnauthenticated(cert, key)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(plain, content) {
			t.Fatal("plaintext mismatch")
		}
		var encoded bytes.Buffer
		if err := cms.EncryptEnveloped2012To(&encoded, bytes.NewReader(content), []*gostx509.Certificate{cert}, algorithm); err != nil {
			t.Fatal(err)
		}
		streamed, err := cms.ParseEnvelopedData(encoded.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		var restored bytes.Buffer
		if err := streamed.DecryptUnauthenticatedTo(&restored, cert, key); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(restored.Bytes(), content) {
			t.Fatal("streamed plaintext mismatch")
		}
	}
	if err := cms.EncryptEnveloped2012To(shortWriter{}, bytes.NewReader([]byte("x")), []*gostx509.Certificate{cert}, keywrap.AlgorithmKuznechik); err == nil {
		t.Fatal("short write accepted")
	}
}
