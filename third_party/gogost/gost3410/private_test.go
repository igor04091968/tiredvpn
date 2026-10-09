package gost3410

import (
	"crypto"
	"crypto/rand"
	"testing"
)

func TestSignerInterface(t *testing.T) {
	c := CurveIdGostR34102001TestParamSet()
	prv, err := GenPrivateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var _ crypto.Signer = prv
	var _ crypto.Signer = &PrivateKeyReverseDigest{}
	var _ crypto.Signer = &PrivateKeyReverseDigestAndSignature{}
}

func TestSignerReverseDigest(t *testing.T) {
	dgst := make([]byte, 32)
	rand.Read(dgst)
	prv0, err := GenPrivateKey(CurveIdGostR34102001TestParamSet(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub0 := prv0.Public().(*PublicKey)
	sign, err := prv0.Sign(rand.Reader, dgst, nil)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := pub0.VerifyDigest(dgst, sign)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.FailNow()
	}
	var _ crypto.PublicKey = pub0

	prv1 := PrivateKeyReverseDigest{prv0}
	pub1 := PublicKeyReverseDigest{prv1.Public().(*PublicKey)}
	sign, err = prv1.Sign(rand.Reader, dgst, nil)
	if err != nil {
		t.Fatal(err)
	}
	valid, err = pub1.VerifyDigest(dgst, sign)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.FailNow()
	}

	prv2 := PrivateKeyReverseDigestAndSignature{prv0}
	pub2 := PublicKeyReverseDigestAndSignature{prv2.Public().(*PublicKey)}
	sign, err = prv2.Sign(rand.Reader, dgst, nil)
	if err != nil {
		t.Fatal(err)
	}
	valid, err = pub2.VerifyDigest(dgst, sign)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.FailNow()
	}
}
