package cms_test

import (
	"bytes"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"gitverse.ru/uzer_007/gogost/v3/cms"
	"gitverse.ru/uzer_007/gogost/v3/gost3410"
	"gitverse.ru/uzer_007/gogost/v3/gostx509"
	"gitverse.ru/uzer_007/gogost/v3/keywrap"
)

// This opt-in integration test generates test keys on the host running
// OpenSSL. No private key is transferred between machines or kept in fixtures.
func TestOpenSSLDecryptOurModernCMS(t *testing.T) {
	if os.Getenv("GOGOST_OPENSSL_INTEROP") != "1" {
		t.Skip("OpenSSL GOST integration test is opt-in")
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip(err)
	}
	for _, tc := range []struct {
		name      string
		curve     *gost3410.Curve
		algorithm keywrap.Algorithm
	}{
		{"kuz256", gost3410.CurveIdtc26gost341012256paramSetB(), keywrap.AlgorithmKuznechik},
		{"magma256", gost3410.CurveIdtc26gost341012256paramSetB(), keywrap.AlgorithmMagma},
		{"kuz512", gost3410.CurveIdtc26gost341012512paramSetA(), keywrap.AlgorithmKuznechik},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := gost3410.GenPrivateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			pub, err := key.PublicKey()
			if err != nil {
				t.Fatal(err)
			}
			template := &gostx509.Certificate{
				SerialNumber: big.NewInt(9103), Subject: pkix.Name{CommonName: "OpenSSL CMS integration"},
				NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
				KeyUsage: gostx509.KeyUsageKeyAgreement, BasicConstraintsValid: true,
			}
			certDER, err := gostx509.CreateCertificate(rand.Reader, template, template, pub, key)
			if err != nil {
				t.Fatal(err)
			}
			cert, err := gostx509.ParseCertificate(certDER)
			if err != nil {
				t.Fatal(err)
			}
			privateDER, err := gostx509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(privateDER)
			content := bytes.Repeat([]byte("OpenSSL verifies Go CMS\n"), 40)
			envelope, err := cms.EncryptEnveloped2012(content, []*gostx509.Certificate{cert}, tc.algorithm)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			keyPath := filepath.Join(dir, "key.pem")
			certPath := filepath.Join(dir, "cert.pem")
			encodedPath := filepath.Join(dir, "envelope.der")
			plainPath := filepath.Join(dir, "plain.txt")
			if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(encodedPath, envelope, 0600); err != nil {
				t.Fatal(err)
			}
			command := exec.Command("openssl", "cms", "-decrypt", "-binary", "-engine", "gost", "-inform", "DER", "-in", encodedPath, "-recip", certPath, "-inkey", keyPath, "-out", plainPath)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("OpenSSL decryption: %v: %s", err, output)
			}
			plain, err := os.ReadFile(plainPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(plain, content) {
				t.Fatal("OpenSSL plaintext mismatch")
			}
			streamPath := filepath.Join(dir, "stream-envelope.ber")
			stream, err := os.Create(streamPath)
			if err != nil {
				t.Fatal(err)
			}
			streamErr := cms.EncryptEnveloped2012To(stream, bytes.NewReader(content), []*gostx509.Certificate{cert}, tc.algorithm)
			closeErr := stream.Close()
			if streamErr != nil || closeErr != nil {
				t.Fatalf("stream encryption: %v; close: %v", streamErr, closeErr)
			}
			command = exec.Command("openssl", "cms", "-decrypt", "-binary", "-engine", "gost", "-inform", "DER", "-in", streamPath, "-recip", certPath, "-inkey", keyPath, "-out", plainPath)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("OpenSSL BER decryption: %v: %s", err, output)
			}
			plain, err = os.ReadFile(plainPath)
			if err != nil || !bytes.Equal(plain, content) {
				t.Fatalf("OpenSSL BER plaintext mismatch: %v", err)
			}
			// The gost-engine CMS encrypt path selects the CMS section size;
			// its decrypt path currently loses that parameter on reinit for
			// messages crossing the default TLS section boundary. Verify the
			// large, normative ciphertext in the other direction.
			large := bytes.Repeat([]byte("OpenSSL verifies Go CMS\n"), 14000)
			if err := os.WriteFile(plainPath, large, 0600); err != nil {
				t.Fatal(err)
			}
			cipherName := "-kuznyechik-ctr-acpkm"
			if tc.algorithm == keywrap.AlgorithmMagma {
				cipherName = "-magma-ctr-acpkm"
			}
			openSSLPath := filepath.Join(dir, "openssl-envelope.der")
			command = exec.Command("openssl", "cms", "-encrypt", "-binary", "-engine", "gost", cipherName,
				"-in", plainPath, "-outform", "DER", "-out", openSSLPath, certPath)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("OpenSSL encryption: %v: %s", err, output)
			}
			openSSLDER, err := os.ReadFile(openSSLPath)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := cms.ParseEnvelopedData(openSSLDER)
			if err != nil {
				t.Fatal(err)
			}
			fromOpenSSL, err := parsed.DecryptUnauthenticated(cert, key)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(fromOpenSSL, large) {
				t.Fatal("large OpenSSL CMS plaintext mismatch")
			}
		})
	}
}
