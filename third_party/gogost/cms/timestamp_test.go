package cms_test

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"gitverse.ru/uzer_007/gogost/v3/cms"
	"gitverse.ru/uzer_007/gogost/v3/gost3410"
	"gitverse.ru/uzer_007/gogost/v3/gost34112012256"
	"gitverse.ru/uzer_007/gogost/v3/gostx509"
)

func TestRFC3161TimeStampToken(t *testing.T) {
	private, err := gost3410.GenPrivateKey(gost3410.CurveIdtc26gost34102012256paramSetA(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := private.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	ekuValue, err := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}})
	if err != nil {
		t.Fatal(err)
	}
	template := &gostx509.Certificate{SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "TSA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: gostx509.KeyUsageDigitalSignature | gostx509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: ekuValue}}}
	certDER, err := gostx509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := gostx509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := cms.ValidateTSACertificate(cert); err != nil {
		t.Fatal(err)
	}
	message := []byte("signature bytes to stamp")
	h := gost34112012256.New()
	_, _ = h.Write(message)
	digest := h.Sum(nil)
	digestOID := asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 2}
	policy := asn1.ObjectIdentifier{1, 2, 3, 4, 5}
	nonce := big.NewInt(123456)
	request, err := cms.CreateTimeStampRequest(message, digestOID, nonce)
	if err != nil || len(request) == 0 {
		t.Fatalf("request: %v", err)
	}
	encoded, err := cms.SignTimeStampToken(digest, digestOID, policy, big.NewInt(77), nonce, now, cert, private)
	if err != nil {
		t.Fatal(err)
	}
	token, err := cms.ParseTimeStampToken(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !token.Time.Equal(now) || token.Nonce.Cmp(nonce) != 0 || !token.Policy.Equal(policy) {
		t.Fatal("TSTInfo fields changed")
	}
	if err := token.ValidateTSASigner(); err != nil {
		t.Fatal(err)
	}
	if err := token.VerifyImprint(message); err != nil {
		t.Fatal(err)
	}
	if err := token.VerifyImprint([]byte("wrong")); err == nil {
		t.Fatal("wrong imprint accepted")
	}
	results, err := token.VerifySignatures()
	if err != nil || len(results) != 1 || results[0].Err != nil {
		t.Fatalf("signature: %v %v", results, err)
	}
	response, err := asn1.Marshal(struct{ Status, Token asn1.RawValue }{
		asn1.RawValue{FullBytes: []byte{0x30, 0x03, 0x02, 0x01, 0}},
		asn1.RawValue{FullBytes: encoded},
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := cms.ParseTimeStampResponse(response, nonce)
	if err != nil || parsed.SerialNumber.Cmp(big.NewInt(77)) != 0 {
		t.Fatalf("response: %v", err)
	}
	if _, err := cms.ParseTimeStampResponse(response, big.NewInt(8)); err == nil {
		t.Fatal("wrong nonce accepted")
	}
	messageDER, err := cms.SignDetached(message, cert, private)
	if err != nil {
		t.Fatal(err)
	}
	messageSigned, err := cms.ParseSignedData(messageDER)
	if err != nil {
		t.Fatal(err)
	}
	h.Reset()
	_, _ = h.Write(messageSigned.Signers[0].Signature)
	stamp, err := cms.SignTimeStampToken(h.Sum(nil), digestOID, policy, big.NewInt(78), nil, now, cert, private)
	if err != nil {
		t.Fatal(err)
	}
	cades, err := cms.AddSignatureTimeStamp(messageDER, 0, stamp)
	if err != nil {
		t.Fatal(err)
	}
	parsedCAdES, err := cms.ParseSignedData(cades)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsedCAdES.Signers[0].SignatureTimeStamps) != 1 {
		t.Fatal("missing CAdES-T attribute")
	}
	for _, item := range parsedCAdES.VerifySignatureTimeStamps()[0] {
		if item != nil {
			t.Fatal(item)
		}
	}
	verified, err := parsedCAdES.Verify(message)
	if err != nil || len(verified) != 1 || verified[0].Err != nil {
		t.Fatalf("CAdES-T signature: %v %v", verified, err)
	}
	if _, err := cms.AddSignatureTimeStamp(messageDER, 0, encoded); err == nil {
		t.Fatal("timestamp of different bytes accepted")
	}
	secondStamp, err := cms.SignTimeStampToken(h.Sum(nil), digestOID, policy, big.NewInt(79), nil, now, cert, private)
	if err != nil {
		t.Fatal(err)
	}
	doubleStamped, err := cms.AddSignatureTimeStamp(cades, 0, secondStamp)
	if err != nil {
		t.Fatal(err)
	}
	twice, err := cms.ParseSignedData(doubleStamped)
	if err != nil || len(twice.Signers[0].SignatureTimeStamps) != 2 {
		t.Fatalf("multiple timestamp values: %v", err)
	}
	for _, item := range twice.VerifySignatureTimeStamps()[0] {
		if item != nil {
			t.Fatal(item)
		}
	}
}
