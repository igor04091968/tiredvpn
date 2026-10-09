package cms

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"gitverse.ru/uzer_007/gogost/v3/gost3410"
	"gitverse.ru/uzer_007/gogost/v3/gostx509"
)

func TestEnvelopedOptionalAttributesAndUnsupportedRecipient(t *testing.T) {
	certDER, err := os.ReadFile(filepath.Join("testdata", "openssl-modern-envelope", "recipient.der"))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := gostx509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, gost3410.CurveDefault().PointSize())
	for i := range raw {
		raw[i] = 55 + byte(i+1)
	}
	private, err := gost3410.NewPrivateKey(gost3410.CurveDefault(), raw)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("optional CMS fields")
	encoded, err := EncryptEnvelopedLegacy(content, []*gostx509.Certificate{cert})
	if err != nil {
		t.Fatal(err)
	}
	_, outer, _, err := readExpected(encoded, 0x30)
	if err != nil {
		t.Fatal(err)
	}
	_, outer, err = parseOID(outer)
	if err != nil {
		t.Fatal(err)
	}
	_, explicit, _, err := readExpected(outer, 0xa0)
	if err != nil {
		t.Fatal(err)
	}
	_, envelope, _, err := readExpected(explicit, 0x30)
	if err != nil {
		t.Fatal(err)
	}
	_, envelope, err = parseSmallInt(envelope)
	if err != nil {
		t.Fatal(err)
	}
	_, recipients, eci, err := readExpected(envelope, 0x31)
	if err != nil {
		t.Fatal(err)
	}
	_, encryptedInfo, tail, err := readExpected(eci, 0x30)
	if err != nil || len(tail) != 0 {
		t.Fatal(err)
	}
	// OtherRecipientInfo ([4] IMPLICIT) is unsupported here but can coexist
	// with the supported KeyTransRecipientInfo.
	otherRecipient := derWrap(0xa4, derOID([]int{1, 2, 3, 4}), derWrap(0x04, []byte{1}))
	attribute := makeAttribute([]int{1, 2, 3, 5}, derWrap(0x04, []byte("metadata")))
	attrs := derWrap(0xa1, attribute)
	mutated := derWrap(0x30, derOID(oidEnvelopedData), derWrap(0xa0,
		derWrap(0x30, []byte{0x02, 0x01, 0x02}, derSet(recipients, otherRecipient),
			derWrap(0x30, encryptedInfo), attrs)))
	parsed, err := ParseEnvelopedData(mutated)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Recipients) != 1 || !bytes.Equal(parsed.UnprotectedAttributes, attrs) {
		t.Fatal("optional fields were lost")
	}
	plain, err := parsed.DecryptUnauthenticated(cert, private)
	if err != nil || !bytes.Equal(plain, content) {
		t.Fatalf("decrypt: %v", err)
	}
	corrupt := bytes.Clone(mutated)
	corrupt[len(corrupt)-len(attrs)+2] = 0xff
	if _, err := ParseEnvelopedData(corrupt); err == nil {
		t.Fatal("accepted malformed unprotected attribute")
	}
}
