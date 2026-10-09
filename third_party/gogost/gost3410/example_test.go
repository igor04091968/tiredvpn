package gost3410_test

import (
	"bytes"
	"fmt"

	"gitverse.ru/uzer_007/gogost/v3/gost3410"
)

func Example() {
	curve := gost3410.CurveIdGostR34102001TestParamSet()
	privateRaw := bytes.Repeat([]byte{0x01}, curve.PointSize())
	privateKey, err := gost3410.NewPrivateKey(curve, privateRaw)
	if err != nil {
		panic(err)
	}

	publicKey, err := privateKey.PublicKey()
	if err != nil {
		panic(err)
	}

	digest := bytes.Repeat([]byte{0x02}, curve.PointSize())
	signatureRand := bytes.NewReader(bytes.Repeat([]byte{0x03}, 4*curve.PointSize()))
	signature, err := privateKey.SignDigest(digest, signatureRand)
	if err != nil {
		panic(err)
	}

	valid, err := publicKey.VerifyDigest(digest, signature)
	if err != nil {
		panic(err)
	}
	fmt.Println(valid)
	// Output: true
}
