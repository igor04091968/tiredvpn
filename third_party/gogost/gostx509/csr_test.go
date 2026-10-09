package gostx509

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"testing"

	"gitverse.ru/uzer_007/gogost/v3/gost3410"
)

func TestGOSTCertificateRequest(t *testing.T) {
	for _, curve := range []*gost3410.Curve{
		gost3410.CurveIdtc26gost34102012256paramSetA(),
		gost3410.CurveIdtc26gost34102012512paramSetA(),
		gost3410.CurveIdGostR34102001CryptoProAParamSet(),
	} {
		t.Run(curve.Name, func(t *testing.T) {
			private, _ := generateKey(t, curve)
			der, err := CreateCertificateRequest(rand.Reader, &CertificateRequest{
				Subject:  pkix.Name{CommonName: "ГОСТ-запрос"},
				DNSNames: []string{"example.org"},
			}, private)
			if err != nil {
				t.Fatal(err)
			}
			request, err := ParseCertificateRequest(der)
			if err != nil {
				t.Fatal(err)
			}
			if request.Subject.CommonName != "ГОСТ-запрос" || request.PublicKeyAlgorithm != GOST {
				t.Fatalf("unexpected request: %s %v", request.Subject.CommonName, request.PublicKeyAlgorithm)
			}
			if err := request.CheckSignature(); err != nil {
				t.Fatal(err)
			}
			request.RawTBSCertificateRequest[10] ^= 1
			if err := request.CheckSignature(); err == nil {
				t.Fatal("tampered request accepted")
			}
		})
	}
}
