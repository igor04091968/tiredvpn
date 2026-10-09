package gostx509

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestGo127Aliases(t *testing.T) {
	if MLDSA44 != stdx509.MLDSA44 || MLDSA65 != stdx509.MLDSA65 || MLDSA87 != stdx509.MLDSA87 {
		t.Fatal("ML-DSA signature algorithm aliases differ from crypto/x509")
	}
	if MLDSA != stdx509.MLDSA {
		t.Fatal("ML-DSA public key algorithm alias differs from crypto/x509")
	}
}

func TestGo127RawSignatureAlgorithm(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &stdx509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "go127.example"},
		NotBefore:    time.Unix(1, 0),
		NotAfter:     time.Unix(2, 0),
		KeyUsage:     stdx509.KeyUsageDigitalSignature,
	}
	der, err := stdx509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	want, err := stdx509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.RawSignatureAlgorithm, want.RawSignatureAlgorithm) {
		t.Fatalf("RawSignatureAlgorithm = %x, want %x", got.RawSignatureAlgorithm, want.RawSignatureAlgorithm)
	}
}

func TestGo127MLDSADelegation(t *testing.T) {
	private, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	parsedPrivate, err := ParsePKCS8PrivateKey(privateDER)
	if err != nil {
		t.Fatal(err)
	}
	if !private.Equal(parsedPrivate) {
		t.Fatal("ML-DSA PKCS #8 round-trip changed the private key")
	}

	publicDER, err := MarshalPKIXPublicKey(private.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	parsedPublic, err := ParsePKIXPublicKey(publicDER)
	if err != nil {
		t.Fatal(err)
	}
	if !private.PublicKey().Equal(parsedPublic) {
		t.Fatal("ML-DSA PKIX round-trip changed the public key")
	}
}
