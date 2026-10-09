package gostx509

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	"gitverse.ru/uzer_007/gogost/v3/gost3410"
	"gitverse.ru/uzer_007/gogost/v3/gost34112012256"
)

func TestCertificateInfoParseAndVerifyChain(t *testing.T) {
	rootKey := certificateInfoPrivateKey(t, gost3410.CurveIdtc26gost34102012256paramSetA(), 0x41)
	leafKey := certificateInfoPrivateKey(t, gost3410.CurveIdtc26gost34102012256paramSetA(), 0x42)
	rootDER := certificateInfoCertificate(t, "Info Root", "root@example.test", rootKey, rootKey, nil, 41, true)
	root, err := ParseCertificateInfoDER(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafDER := certificateInfoCertificate(t, "Info Leaf", "leaf@example.test", leafKey, rootKey, rootDER, 42, false)
	leaf, err := ParseCertificateInfoDER(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.CN != "Info Leaf" || leaf.Email != "leaf@example.test" || leaf.Organization != "Gamma" {
		t.Fatalf("unexpected certificate metadata: %+v", leaf)
	}
	if leaf.PublicKeyAlgorithm != GOSTAlgorithm34102012256 || leaf.CurveOID != oidTc26Gost341012256ParamSetA.String() {
		t.Fatalf("unexpected public-key metadata: algorithm=%q curve=%q", leaf.PublicKeyAlgorithm, leaf.CurveOID)
	}
	if err := VerifyCertificateInfoChain(leaf, nil, ChainVerifyOptions{TrustedRoots: []*CertificateInfo{root}}); err != nil {
		t.Fatal(err)
	}
}

func TestCertificateInfoOwnsCryptographicFields(t *testing.T) {
	key := certificateInfoPrivateKey(t, gost3410.CurveIdtc26gost34102012256paramSetA(), 0x51)
	der := certificateInfoCertificate(t, "Owned", "owned@example.test", key, key, nil, 51, true)
	certificate, err := ParseCertificateInfoDER(der)
	if err != nil {
		t.Fatal(err)
	}
	fields := [][]byte{
		certificate.RawDER, certificate.TBSCertificateDER, certificate.Signature,
		certificate.subjectRaw, certificate.issuerRaw, certificate.PublicKey.PublicKeyRaw,
	}
	for index, field := range fields {
		if len(field) == 0 || cap(field) != len(field) {
			t.Fatalf("field %d length/capacity = %d/%d", index, len(field), cap(field))
		}
	}
	originalTBS := bytes.Clone(certificate.TBSCertificateDER)
	for index := range der {
		der[index] = 0
	}
	if !bytes.Equal(certificate.TBSCertificateDER, originalTBS) {
		t.Fatal("parsed fields alias caller-owned DER")
	}
}

func TestParseCertificateInfoDoesNotTrimBinaryDER(t *testing.T) {
	key := certificateInfoPrivateKey(t, gost3410.CurveIdtc26gost34102012256paramSetA(), 0x52)
	der := certificateInfoCertificate(t, "Binary DER", "binary@example.test", key, key, nil, 52, true)
	der[len(der)-1] = 0x20

	certificate, err := ParseCertificateInfo(der)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(certificate.RawDER, der) {
		t.Fatal("binary DER was modified before parsing")
	}
}

func TestCertificateInfoGOST2001Profile(t *testing.T) {
	key := certificateInfoPrivateKey(t, gost3410.CurveIdGostR34102001CryptoProAParamSet(), 0x61)
	der := certificateInfoCertificate(t, "GOST 2001", "gost2001@example.test", key, key, nil, 61, true)
	info, err := ParseCertificateInfoDER(der)
	if err != nil {
		t.Fatal(err)
	}
	if info.PublicKeyAlgorithm != GOSTAlgorithm34102001 || info.DigestAlgorithm != GOSTDigestAlgorithm341194 {
		t.Fatalf("unexpected GOST 2001 metadata: %+v", info)
	}
	if err := VerifyCertificateInfoSignature(info, info); err != nil {
		t.Fatal(err)
	}
	certificate, err := ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if certificate.SignatureAlgorithm != GOST2001 {
		t.Fatalf("signature algorithm = %v, want GOST2001", certificate.SignatureAlgorithm)
	}
	if err := certificate.CheckSignatureFrom(certificate); err != nil {
		t.Fatal(err)
	}
}

func TestCertificateInfoGOST2012512Profile(t *testing.T) {
	key := certificateInfoPrivateKey(t, gost3410.CurveIdtc26gost34102012512paramSetA(), 0x62)
	der := certificateInfoCertificate(t, "GOST 2012-512", "gost512@example.test", key, key, nil, 62, true)
	info, err := ParseCertificateInfoDER(der)
	if err != nil {
		t.Fatal(err)
	}
	if info.PublicKeyAlgorithm != GOSTAlgorithm34102012512 || info.DigestAlgorithm != GOSTDigestAlgorithm2012512 {
		t.Fatalf("unexpected GOST 2012-512 metadata: %+v", info)
	}
	if err := VerifyCertificateInfoSignature(info, info); err != nil {
		t.Fatal(err)
	}
}

func TestCertificateInfoPublicKeyRoundTrip(t *testing.T) {
	key := certificateInfoPrivateKey(t, gost3410.CurveIdtc26gost34102012256paramSetA(), 0x71)
	der := certificateInfoCertificate(t, "Round Trip", "roundtrip@example.test", key, key, nil, 71, true)
	certificate, err := ParseCertificateInfoDER(der)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := MarshalPublicKeyInfoDER(certificate.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePublicKeyInfoDER(publicDER)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed.PublicKeyRaw, certificate.PublicKey.PublicKeyRaw) || parsed.CurveOID != certificate.CurveOID {
		t.Fatal("public-key metadata changed after round trip")
	}
}

func TestCertificateInfoChainLimitsSignatureAttempts(t *testing.T) {
	rootKey := certificateInfoPrivateKey(t, gost3410.CurveIdtc26gost34102012256paramSetA(), 0x72)
	leafKey := certificateInfoPrivateKey(t, gost3410.CurveIdtc26gost34102012256paramSetA(), 0x73)
	wrongKey := certificateInfoPrivateKey(t, gost3410.CurveIdtc26gost34102012256paramSetA(), 0x74)
	rootDER := certificateInfoCertificate(t, "Bounded Root", "root@example.test", rootKey, rootKey, nil, 72, true)
	root, err := ParseCertificateInfoDER(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafDER := certificateInfoCertificate(t, "Bounded Leaf", "leaf@example.test", leafKey, rootKey, rootDER, 73, false)
	leaf, err := ParseCertificateInfoDER(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf.AuthorityKeyID = nil
	wrongPublicKey, err := wrongKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	intermediates := make([]*CertificateInfo, maxChainSignatureChecks+1)
	for index := range intermediates {
		candidate := *root
		candidate.RawDER = append(bytes.Clone(root.RawDER), byte(index))
		publicKey := *root.PublicKey
		publicKey.PublicKey = wrongPublicKey
		publicKey.PublicKeyRaw = wrongPublicKey.Raw()
		candidate.PublicKey = &publicKey
		intermediates[index] = &candidate
	}

	err = VerifyCertificateInfoChain(leaf, intermediates, ChainVerifyOptions{TrustedRoots: []*CertificateInfo{root}})
	if !errors.Is(err, ErrCertificateVerification) || !errors.Is(err, errSignatureLimit) {
		t.Fatalf("expected bounded signature-check failure, got %v", err)
	}
}

func BenchmarkParseCertificateInfoDER(b *testing.B) {
	key := certificateInfoPrivateKey(b, gost3410.CurveIdtc26gost34102012256paramSetA(), 0x91)
	der := certificateInfoBenchmarkDER(b, "Bench Parse", "parse@example.test", key, 91)
	b.ReportAllocs()
	b.SetBytes(int64(len(der)))
	b.ResetTimer()
	for b.Loop() {
		if _, err := ParseCertificateInfoDER(der); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseCertificateGOST(b *testing.B) {
	key := certificateInfoPrivateKey(b, gost3410.CurveIdtc26gost34102012256paramSetA(), 0x94)
	der := certificateInfoBenchmarkDER(b, "Bench Full Parse", "full-parse@example.test", key, 94)
	b.ReportAllocs()
	b.SetBytes(int64(len(der)))
	b.ResetTimer()
	for b.Loop() {
		if _, err := ParseCertificate(der); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyDetachedSignatureInfo(b *testing.B) {
	key := certificateInfoPrivateKey(b, gost3410.CurveIdtc26gost34102012256paramSetA(), 0x92)
	der := certificateInfoBenchmarkDER(b, "Bench Verify", "verify@example.test", key, 92)
	certificate, err := ParseCertificateInfoDER(der)
	if err != nil {
		b.Fatal(err)
	}
	data := bytes.Repeat([]byte("license signature payload"), 32)
	digest := gost34112012256.Sum(data)
	signature, err := key.SignDigest(digest[:], bytes.NewReader(bytes.Repeat([]byte{0x93}, 4096)))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for b.Loop() {
		if err := VerifyDetachedSignatureInfo(data, signature, certificate); err != nil {
			b.Fatal(err)
		}
	}
}

func certificateInfoBenchmarkDER(tb testing.TB, commonName, email string, key *gost3410.PrivateKey, serial int64) []byte {
	tb.Helper()
	nameDER, err := asn1.Marshal(pkix.RDNSequence{
		{{Type: oidNameCommonName, Value: commonName}},
		{{Type: oidNameOrganization, Value: "Gamma"}},
		{{Type: oidEmailAddress, Value: email}},
	})
	if err != nil {
		tb.Fatal(err)
	}
	var name asn1.RawValue
	if rest, err := asn1.Unmarshal(nameDER, &name); err != nil || len(rest) != 0 {
		tb.Fatal(err)
	}
	publicKey, err := key.PublicKey()
	if err != nil {
		tb.Fatal(err)
	}
	paramsDER, err := asn1.Marshal(gostPublicKeyInfoParameters{
		PublicKeyParamSet: oidTc26Gost341012256ParamSetA,
		DigestParamSet:    oidTc26Gost34112012256,
	})
	if err != nil {
		tb.Fatal(err)
	}
	publicKeyDER, err := asn1.Marshal(publicKey.Raw())
	if err != nil {
		tb.Fatal(err)
	}
	algorithm := algorithmIdentifierASN1{Algorithm: oidTc26Gost341012256Signature}
	now := time.Now().UTC()
	tbs := tbsCertificateInfoASN1{
		Version: 2, SerialNumber: big.NewInt(serial), Signature: algorithm,
		Issuer: name, Subject: name,
		Validity: validityInfoASN1{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)},
		SubjectPublicKeyInfo: subjectPublicKeyInfoMetadataASN1{
			Algorithm: algorithmIdentifierASN1{
				Algorithm:  oidTc26Gost341012256,
				Parameters: asn1.RawValue{FullBytes: paramsDER},
			},
			SubjectPublicKey: asn1.BitString{Bytes: publicKeyDER, BitLength: len(publicKeyDER) * 8},
		},
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		tb.Fatal(err)
	}
	digest := gost34112012256.Sum(tbsDER)
	signature, err := key.SignDigest(digest[:], bytes.NewReader(bytes.Repeat([]byte{byte(serial + 0x60)}, 4096)))
	if err != nil {
		tb.Fatal(err)
	}
	der, err := asn1.Marshal(certificateInfoASN1{
		TBSCertificate: tbs, SignatureAlgorithm: algorithm,
		SignatureValue: asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
	if err != nil {
		tb.Fatal(err)
	}
	return der
}

func certificateInfoPrivateKey(tb testing.TB, curve *gost3410.Curve, seed byte) *gost3410.PrivateKey {
	tb.Helper()
	candidate := new(big.Int).SetBytes(bytes.Repeat([]byte{seed}, curve.PointSize()))
	candidate.Mod(candidate, new(big.Int).Sub(curve.Q, big.NewInt(1)))
	candidate.Add(candidate, big.NewInt(1))
	key, err := gost3410.NewPrivateKeyBE(curve, candidate.FillBytes(make([]byte, curve.PointSize())))
	if err != nil {
		tb.Fatal(err)
	}
	return key
}

func certificateInfoCertificate(
	tb testing.TB,
	commonName, email string,
	subjectKey, issuerKey *gost3410.PrivateKey,
	issuerDER []byte,
	serial int64,
	isCA bool,
) []byte {
	tb.Helper()
	publicKey, err := subjectKey.PublicKey()
	if err != nil {
		tb.Fatal(err)
	}
	name := pkix.Name{
		CommonName:   commonName,
		Organization: []string{"Gamma"},
		ExtraNames: []pkix.AttributeTypeAndValue{{
			Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, Value: email,
		}},
	}
	now := time.Now().UTC()
	template := &Certificate{
		SerialNumber: big.NewInt(serial), Subject: name,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		BasicConstraintsValid: isCA, IsCA: isCA,
	}
	if isCA {
		template.KeyUsage = KeyUsageCertSign
	}
	parent := template
	if len(issuerDER) != 0 {
		parent, err = ParseCertificate(issuerDER)
		if err != nil {
			tb.Fatal(err)
		}
	}
	der, err := CreateCertificate(
		bytes.NewReader(bytes.Repeat([]byte{byte(serial + 0x60)}, 8192)),
		template, parent, publicKey, issuerKey,
	)
	if err != nil {
		tb.Fatal(err)
	}
	return der
}
