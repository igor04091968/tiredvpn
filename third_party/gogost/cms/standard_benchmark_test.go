package cms_test

import (
	"bytes"
	"crypto/rand"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"testing"
	"time"

	"gitverse.ru/uzer_007/gogost/v3/cms"
	"gitverse.ru/uzer_007/gogost/v3/gostx509"
)

var standardCMSResult []byte

// BenchmarkStandardCMS measures signature and encryption paths independently.
func BenchmarkStandardCMS(b *testing.B) {
	signer := testRecipient(b, 33)
	pub, err := signer.PublicKey()
	if err != nil {
		b.Fatal(err)
	}
	now := time.Now()
	template := &gostx509.Certificate{
		SerialNumber: big.NewInt(501), Subject: pkix.Name{CommonName: "CMS benchmark"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: gostx509.KeyUsageDigitalSignature | gostx509.KeyUsageCertSign,
		IsCA:     true, BasicConstraintsValid: true,
	}
	certDER, err := gostx509.CreateCertificate(rand.Reader, template, template, pub, signer)
	if err != nil {
		b.Fatal(err)
	}
	cert, err := gostx509.ParseCertificate(certDER)
	if err != nil {
		b.Fatal(err)
	}
	recipient, recipientKey := cms2001Identity(b, 502)
	for _, size := range []int{1024, 4096, 1 << 20, 64 << 20} {
		content := make([]byte, size)
		for i := range content {
			content[i] = byte(i)
		}
		signature, err := cms.SignDetached(content, cert, signer)
		if err != nil {
			b.Fatal(err)
		}
		signed, err := cms.ParseSignedData(signature)
		if err != nil {
			b.Fatal(err)
		}
		envelopeDER, err := cms.EncryptEnveloped(content, []*gostx509.Certificate{recipient})
		if err != nil {
			b.Fatal(err)
		}
		envelope, err := cms.ParseEnvelopedData(envelopeDER)
		if err != nil {
			b.Fatal(err)
		}
		name := fmt.Sprintf("%dB", size)
		b.Run("signDetached/"+name, func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				standardCMSResult, err = cms.SignDetachedReader(bytes.NewReader(content), cert, signer)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("verifyDetached/"+name, func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				results, e := signed.VerifyReader(bytes.NewReader(content))
				if e != nil || len(results) != 1 || results[0].Err != nil {
					b.Fatalf("verify: %v %v", results, e)
				}
			}
		})
		b.Run("parseVerifyDetached/"+name, func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				parsed, e := cms.ParseSignedData(signature)
				if e != nil {
					b.Fatal(e)
				}
				results, e := parsed.Verify(content)
				if e != nil || len(results) != 1 || results[0].Err != nil {
					b.Fatalf("verify: %v %v", results, e)
				}
			}
		})
		b.Run("parseSigned/"+name, func(b *testing.B) {
			b.SetBytes(int64(len(signature)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, e := cms.ParseSignedData(signature); e != nil {
					b.Fatal(e)
				}
			}
		})
		b.Run("encryptBER/"+name, func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if e := cms.EncryptEnvelopedTo(io.Discard, bytes.NewReader(content), []*gostx509.Certificate{recipient}); e != nil {
					b.Fatal(e)
				}
			}
		})
		b.Run("decryptTo/"+name, func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if e := envelope.DecryptUnauthenticatedTo(io.Discard, recipient, recipientKey); e != nil {
					b.Fatal(e)
				}
			}
		})
		b.Run("parseEnveloped/"+name, func(b *testing.B) {
			b.SetBytes(int64(len(envelopeDER)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, e := cms.ParseEnvelopedData(envelopeDER); e != nil {
					b.Fatal(e)
				}
			}
		})
	}
}
