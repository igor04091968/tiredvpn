package cms_test

import (
	"bytes"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"testing"
	"time"

	"gitverse.ru/uzer_007/gogost/v3/cms"
	"gitverse.ru/uzer_007/gogost/v3/gost3410"
	"gitverse.ru/uzer_007/gogost/v3/gostx509"
)

func TestSignedDataDetachedAndAttached(t *testing.T) {
	key := testRecipient(t, 4)
	pub, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	template := &gostx509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "CMS test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: gostx509.KeyUsageDigitalSignature | gostx509.KeyUsageCertSign,
		IsCA:     true, BasicConstraintsValid: true,
	}
	certDER, err := gostx509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := gostx509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("CMS signed content")
	for _, attached := range []bool{false, true} {
		var der []byte
		if attached {
			der, err = cms.SignAttached(content, cert, key)
		} else {
			der, err = cms.SignDetachedReader(bytes.NewReader(content), cert, key)
		}
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := cms.ParseSignedData(der)
		if err != nil {
			t.Fatal(err)
		}
		var results []cms.SignerResult
		if attached {
			results, err = parsed.Verify(nil)
		} else {
			results, err = parsed.VerifyReader(bytes.NewReader(content))
		}
		if err != nil || len(results) != 1 || results[0].Err != nil {
			t.Fatalf("verify attached=%v: results=%v err=%v", attached, results, err)
		}
		if attached {
			ber, err := signedContentAsConstructedBER(der, content)
			if err != nil {
				t.Fatal(err)
			}
			berSigned, err := cms.ParseSignedData(ber)
			if err != nil {
				t.Fatal(err)
			}
			results, err := berSigned.Verify(nil)
			if err != nil || len(results) != 1 || results[0].Err != nil {
				t.Fatalf("BER verify: %v %v", results, err)
			}
		}
		if !attached {
			results, err = parsed.Verify([]byte("tampered"))
			if err != nil || results[0].Err == nil {
				t.Fatalf("tamper accepted: %v %v", results, err)
			}
			parsed.Signers[0].Certificate = nil
			results, err = parsed.VerifyReaderWithCertificates(bytes.NewReader(content), []*gostx509.Certificate{cert})
			if err != nil || results[0].Err != nil {
				t.Fatalf("external signer certificate: %v %v", results, err)
			}
		}
	}
}

func TestSignedDataAttachedStreamingBER(t *testing.T) {
	key := testRecipient(t, 9)
	pub, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &gostx509.Certificate{
		SerialNumber: big.NewInt(91), Subject: pkix.Name{CommonName: "streaming signer"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: gostx509.KeyUsageDigitalSignature | gostx509.KeyUsageCertSign,
		IsCA:     true, BasicConstraintsValid: true,
	}
	certDER, err := gostx509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := gostx509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	content := bytes.Repeat([]byte("attached stream;"), 70000)
	var output bytes.Buffer
	if err := cms.SignAttachedTo(&output, bytes.NewReader(content), cert, key); err != nil {
		t.Fatal(err)
	}
	signed, err := cms.ParseSignedData(output.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	results, err := signed.Verify(nil)
	if err != nil || len(results) != 1 || results[0].Err != nil {
		t.Fatalf("signature: %v %v", results, err)
	}
	reader, err := signed.ContentReader()
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := io.ReadAll(reader)
	if err != nil || !bytes.Equal(recovered, content) {
		t.Fatalf("attached content: %v", err)
	}
	if _, err := signed.Verify(content); err == nil {
		t.Fatal("external bytes accepted for attached SignedData")
	}
	if err := cms.SignAttachedTo(shortWriter{}, bytes.NewReader(content), cert, key); err != io.ErrShortWrite {
		t.Fatalf("short writer: %v", err)
	}
}

func TestSignedDataTwoDigestAlgorithms(t *testing.T) {
	content := []byte("two independent CMS signers")
	makeSigner := func(curve *gost3410.Curve, serial int64) ([]byte, *gostx509.Certificate) {
		key, err := gost3410.GenPrivateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := key.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		template := &gostx509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: fmt.Sprint("signer ", serial)},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			KeyUsage: gostx509.KeyUsageDigitalSignature | gostx509.KeyUsageCertSign,
			IsCA:     true, BasicConstraintsValid: true,
		}
		certDER, err := gostx509.CreateCertificate(rand.Reader, template, template, pub, key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := gostx509.ParseCertificate(certDER)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := cms.SignDetached(content, cert, key)
		if err != nil {
			t.Fatal(err)
		}
		return encoded, cert
	}
	first, firstCert := makeSigner(gost3410.CurveIdtc26gost34102012256paramSetA(), 111)
	second, secondCert := makeSigner(gost3410.CurveIdtc26gost34102012512paramSetA(), 112)
	take := func(in []byte) ([]byte, []byte) {
		_, full, _, rest, err := splitDERTest(in)
		if err != nil {
			t.Fatal(err)
		}
		return full, rest
	}
	parts := func(encoded []byte) (version, digestAlgorithm, encap, info []byte) {
		_, _, outer, _, err := splitDERTest(encoded)
		if err != nil {
			t.Fatal(err)
		}
		_, rest := take(outer) // content type
		_, _, explicit, _, err := splitDERTest(rest)
		if err != nil {
			t.Fatal(err)
		}
		_, _, signed, _, err := splitDERTest(explicit)
		if err != nil {
			t.Fatal(err)
		}
		version, signed = take(signed)
		_, _, algBody, next, err := splitDERTest(signed)
		if err != nil {
			t.Fatal(err)
		}
		signed = next
		digestAlgorithm, _ = take(algBody)
		encap, signed = take(signed)
		_, signed = take(signed) // certificate set
		_, _, infoBody, _, err := splitDERTest(signed)
		if err != nil {
			t.Fatal(err)
		}
		info, _ = take(infoBody)
		return
	}
	version, digest1, encap, info1 := parts(first)
	_, digest2, _, info2 := parts(second)
	message := berConstructed(0x30,
		[]byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02},
		berConstructed(0xa0, berConstructed(0x30,
			version, berConstructed(0x31, digest1, digest2), encap,
			berConstructed(0xa0, firstCert.Raw, secondCert.Raw),
			berConstructed(0x31, info1, info2))))
	signed, err := cms.ParseSignedData(message)
	if err != nil {
		t.Fatal(err)
	}
	results, err := signed.Verify(content)
	if err != nil || len(results) != 2 || results[0].Err != nil || results[1].Err != nil {
		t.Fatalf("multisigner result: %v %v", results, err)
	}
}

func splitDERTest(in []byte) (byte, []byte, []byte, []byte, error) {
	if len(in) < 2 {
		return 0, nil, nil, nil, fmt.Errorf("short DER")
	}
	n := int(in[1])
	header := 2
	if n&0x80 != 0 {
		count := n & 0x7f
		if count == 0 || count > 4 || len(in) < 2+count {
			return 0, nil, nil, nil, fmt.Errorf("bad length")
		}
		n = 0
		for _, b := range in[2 : 2+count] {
			n = n<<8 | int(b)
		}
		header += count
	}
	if n > len(in)-header {
		return 0, nil, nil, nil, fmt.Errorf("truncated DER")
	}
	return in[0], in[:header+n], in[header : header+n], in[header+n:], nil
}

func berConstructed(tag byte, parts ...[]byte) []byte {
	out := []byte{tag, 0x80}
	for _, p := range parts {
		out = append(out, p...)
	}
	return append(out, 0, 0)
}

func signedContentAsConstructedBER(der, content []byte) ([]byte, error) {
	_, _, outer, _, err := splitDERTest(der)
	if err != nil {
		return nil, err
	}
	_, oid, _, rest, err := splitDERTest(outer)
	if err != nil {
		return nil, err
	}
	_, _, explicit, _, err := splitDERTest(rest)
	if err != nil {
		return nil, err
	}
	_, _, signed, _, err := splitDERTest(explicit)
	if err != nil {
		return nil, err
	}
	_, version, _, signed, err := splitDERTest(signed)
	if err != nil {
		return nil, err
	}
	_, algorithms, _, signed, err := splitDERTest(signed)
	if err != nil {
		return nil, err
	}
	_, _, encap, signed, err := splitDERTest(signed)
	if err != nil {
		return nil, err
	}
	_, contentType, _, encap, err := splitDERTest(encap)
	if err != nil {
		return nil, err
	}
	_, _, econtent, _, err := splitDERTest(encap)
	if err != nil {
		return nil, err
	}
	_, _, actual, _, err := splitDERTest(econtent)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(actual, content) || len(content) > 127 {
		return nil, fmt.Errorf("unexpected content")
	}
	cut := len(content) / 2
	chunks := berConstructed(0x24, append([]byte{0x04, byte(cut)}, content[:cut]...), append([]byte{0x04, byte(len(content) - cut)}, content[cut:]...))
	newEncap := berConstructed(0x30, contentType, berConstructed(0xa0, chunks))
	newSigned := berConstructed(0x30, version, algorithms, newEncap, signed)
	return berConstructed(0x30, oid, berConstructed(0xa0, newSigned)), nil
}

func TestRFC4490SignedDataParses(t *testing.T) {
	// RFC 4490 section 9.1 is an independently encoded attached signature.
	const encoded = "MIIBKAYJKoZIhvcNAQcCoIIBGTCCARUCAQExDDAKBgYqhQMCAgkFADAbBgkqhkiG" +
		"9w0BBwGgDgQMc2FtcGxlIHRleHQKMYHkMIHhAgEBMIGBMG0xHzAdBgNVBAMMFkdv" +
		"c3RSMzQxMC0yMDAxIGV4YW1wbGUxEjAQBgNVBAoMCUNyeXB0b1BybzELMAkGA1UE" +
		"BhMCUlUxKTAnBgkqhkiG9w0BCQEWGkdvc3RSMzQxMC0yMDAxQGV4YW1wbGUuY29t" +
		"AhAr9cYewhG9F8fc1GJmtC4hMAoGBiqFAwICCQUAMAoGBiqFAwICEwUABEDAw0LZ" +
		"P4/+JRERiHe/icPbg0IE1iD5aCqZ9v4wO+T0yPjVtNr74caRZzQfvKZ6DRJ7/RAl" +
		"xlHbjbL0jHF+7XKp"
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := cms.ParseSignedData(der)
	if err != nil {
		t.Fatal(err)
	}
	if signed.Detached || !bytes.Equal(signed.Content, []byte("sample text\n")) || len(signed.Signers) != 1 {
		t.Fatal("RFC 4490 SignedData parsed incorrectly")
	}
	results, err := signed.VerifyReaderWithCertificates(nil, []*gostx509.Certificate{rfc4491Certificate(t)})
	if err != nil || len(results) != 1 || results[0].Err != nil {
		t.Fatalf("RFC 4490 signature: %v %v", results, err)
	}
}

func TestSignedDataOptions(t *testing.T) {
	cert, key := cms2001Identity(t, 1200)
	chain, _ := cms2001Identity(t, 1201)
	contentType := asn1.ObjectIdentifier{1, 2, 643, 100, 113, 7}
	content := []byte("custom CMS content")
	options := &cms.SignOptions{
		ContentType:       contentType,
		OmitSigningTime:   true,
		ExtraCertificates: []*gostx509.Certificate{chain, cert, chain},
	}
	for _, tc := range []struct {
		name string
		sign func() ([]byte, error)
	}{
		{"attached", func() ([]byte, error) { return cms.SignAttachedWithOptions(content, cert, key, options) }},
		{"detached", func() ([]byte, error) { return cms.SignDetachedWithOptions(content, cert, key, options) }},
		{"streaming", func() ([]byte, error) {
			var out bytes.Buffer
			err := cms.SignAttachedToWithOptions(&out, bytes.NewReader(content), cert, key, options)
			return out.Bytes(), err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := tc.sign()
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := cms.ParseSignedData(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if !parsed.ContentType.Equal(contentType) || len(parsed.Certificates) != 2 || !parsed.Signers[0].SigningTime.IsZero() {
				t.Fatal("CMS options were not preserved")
			}
			var results []cms.SignerResult
			if parsed.Detached {
				results, err = parsed.Verify(content)
			} else {
				results, err = parsed.Verify(nil)
			}
			if err != nil || len(results) != 1 || results[0].Err != nil {
				t.Fatalf("verify: %v %v", results, err)
			}
		})
	}
	stamp := time.Date(2025, 3, 12, 8, 10, 11, 0, time.UTC)
	encoded, err := cms.SignDetachedWithOptions(content, cert, key, &cms.SignOptions{SigningTime: &stamp})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := cms.ParseSignedData(encoded)
	if err != nil || !parsed.Signers[0].SigningTime.Equal(stamp) {
		t.Fatalf("explicit signing time: %v", err)
	}
	if _, err := cms.SignAttachedWithOptions(content, cert, key, &cms.SignOptions{
		OmitSigningTime: true, SigningTime: &stamp,
	}); err == nil {
		t.Fatal("accepted contradictory signing time options")
	}
	if _, err := cms.SignAttachedWithOptions(content, cert, key, &cms.SignOptions{
		ContentType: asn1.ObjectIdentifier{3, 4},
	}); err == nil {
		t.Fatal("accepted invalid content type")
	}
}
