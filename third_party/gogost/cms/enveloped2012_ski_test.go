package cms

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"gitverse.ru/uzer_007/gogost/v3/gost3410"
	"gitverse.ru/uzer_007/gogost/v3/gostx509"
	"gitverse.ru/uzer_007/gogost/v3/keywrap"
)

func TestModernRecipientSubjectKeyIdentifier(t *testing.T) {
	dir := filepath.Join("testdata", "openssl-modern-envelope")
	certDER, err := os.ReadFile(filepath.Join(dir, "recipient.der"))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := gostx509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	cert.SubjectKeyId = []byte{1, 3, 3, 7, 9}
	raw := make([]byte, gost3410.CurveDefault().PointSize())
	for i := range raw {
		raw[i] = 55 + byte(i+1)
	}
	private, err := gost3410.NewPrivateKey(gost3410.CurveDefault(), raw)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("SKI recipient")
	der, err := EncryptEnveloped2012(content, []*gostx509.Certificate{cert}, keywrap.AlgorithmKuznechik)
	if err != nil {
		t.Fatal(err)
	}
	_, outer, _, err := readExpected(der, 0x30)
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
	version, envelope, err := parseSmallInt(envelope)
	if err != nil || version != 2 {
		t.Fatal(err)
	}
	_, recipients, eci, err := readExpected(envelope, 0x31)
	if err != nil {
		t.Fatal(err)
	}
	_, recipient, _, err := readExpected(recipients, 0xa1)
	if err != nil {
		t.Fatal(err)
	}
	if kariVersion, rest, e := parseSmallInt(recipient); e != nil || kariVersion != 3 {
		t.Fatal(e)
	} else {
		recipient = rest
	}
	originator, _, recipient, err := readExpected(recipient, 0xa0)
	if err != nil {
		t.Fatal(err)
	}
	ukm, _, recipient, err := readExpected(recipient, 0xa1)
	if err != nil {
		t.Fatal(err)
	}
	algorithm, _, recipient, err := readExpected(recipient, 0x30)
	if err != nil {
		t.Fatal(err)
	}
	_, entries, _, err := readExpected(recipient, 0x30)
	if err != nil {
		t.Fatal(err)
	}
	_, entry, _, err := readExpected(entries, 0x30)
	if err != nil {
		t.Fatal(err)
	}
	_, _, entry, err = readExpected(entry, 0x30)
	if err != nil {
		t.Fatal(err)
	}
	encryptedKey, _, _, err := readExpected(entry, 0x04)
	if err != nil {
		t.Fatal(err)
	}
	newEntry := derWrap(0x30, derWrap(0xa0, derWrap(0x04, cert.SubjectKeyId)), encryptedKey)
	newRecipient := derWrap(0xa1, []byte{0x02, 0x01, 0x03}, originator, ukm, algorithm, derWrap(0x30, newEntry))
	newEnvelope := derWrap(0x30, []byte{0x02, 0x01, 0x02}, derSet(newRecipient), eci)
	changed := derWrap(0x30, derOID(oidEnvelopedData), derWrap(0xa0, newEnvelope))
	parsed, err := ParseEnvelopedData(changed)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Recipients) != 1 || !bytes.Equal(parsed.Recipients[0].SubjectKeyID, cert.SubjectKeyId) {
		t.Fatal("SKI recipient not parsed")
	}
	plain, err := parsed.DecryptUnauthenticated(cert, private)
	if err != nil || !bytes.Equal(plain, content) {
		t.Fatalf("SKI decryption: %v", err)
	}
	cert.SubjectKeyId[0] ^= 1
	if _, err := parsed.DecryptUnauthenticated(cert, private); err != ErrNoRecipient {
		t.Fatalf("wrong SKI: %v", err)
	}
}
