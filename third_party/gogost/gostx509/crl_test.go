package gostx509

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"gitverse.ru/uzer_007/gogost/v3/gost3410"
)

func TestGOSTCRLSignature(t *testing.T) {
	private, public := generateKey(t, gost3410.CurveIdtc26gost34102012256paramSetA())
	now := time.Now().UTC().Truncate(time.Second)
	template := &Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CRL issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: KeyUsageCertSign | KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true}
	certDER, err := CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	_, algorithm, err := gostCertificateSignatureAlgorithm(private.C)
	if err != nil {
		t.Fatal(err)
	}
	tbs, err := asn1.Marshal(struct {
		Version            int
		SignatureAlgorithm pkix.AlgorithmIdentifier
		Issuer             asn1.RawValue
		ThisUpdate         time.Time `asn1:"utc"`
		NextUpdate         time.Time `asn1:"utc"`
	}{1, algorithm, asn1.RawValue{FullBytes: issuer.RawSubject}, now, now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := hashCertificate(GOST256, tbs)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := (&gost3410.PrivateKeyReverseDigest{Prv: private}).Sign(rand.Reader, digest, gostSignerOpts{})
	if err != nil {
		t.Fatal(err)
	}
	crlDER, err := asn1.Marshal(struct {
		TBS                asn1.RawValue
		SignatureAlgorithm pkix.AlgorithmIdentifier
		Signature          asn1.BitString
	}{asn1.RawValue{FullBytes: tbs}, algorithm, asn1.BitString{Bytes: signature, BitLength: len(signature) * 8}})
	if err != nil {
		t.Fatal(err)
	}
	crl, err := ParseRevocationList(crlDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		t.Fatal(err)
	}
	crl.Signature[0] ^= 1
	if err := crl.CheckSignatureFrom(issuer); err == nil {
		t.Fatal("tampered CRL accepted")
	}
}
