package gostx509

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	"gitverse.ru/uzer_007/gogost/v3/gost3410"
)

func generateKey(t *testing.T, curve *gost3410.Curve) (*gost3410.PrivateKey, *gost3410.PublicKey) {
	t.Helper()
	private, err := gost3410.GenPrivateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := private.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return private, public
}

func TestGOSTPublicAndPrivateKeyRoundTrip(t *testing.T) {
	curves := []*gost3410.Curve{
		gost3410.CurveIdtc26gost341012256paramSetA(),
		gost3410.CurveIdtc26gost341012256paramSetB(),
		gost3410.CurveIdtc26gost341012256paramSetC(),
		gost3410.CurveIdtc26gost341012256paramSetD(),
		gost3410.CurveIdtc26gost341012512paramSetA(),
		gost3410.CurveIdtc26gost341012512paramSetB(),
		gost3410.CurveIdtc26gost341012512paramSetC(),
	}
	for _, curve := range curves {
		curve := curve
		t.Run(curve.Name, func(t *testing.T) {
			private, public := generateKey(t, curve)

			publicDER, err := MarshalPKIXPublicKey(public)
			if err != nil {
				t.Fatal(err)
			}
			parsedPublic, err := ParsePKIXPublicKey(publicDER)
			if err != nil {
				t.Fatal(err)
			}
			if !public.Equal(parsedPublic) {
				t.Fatal("public key changed during PKIX round trip")
			}

			privateDER, err := MarshalPKCS8PrivateKey(private)
			if err != nil {
				t.Fatal(err)
			}
			parsedPrivateAny, err := ParsePKCS8PrivateKey(privateDER)
			if err != nil {
				t.Fatal(err)
			}
			parsedPrivate, ok := parsedPrivateAny.(*gost3410.PrivateKey)
			if !ok || !bytes.Equal(private.Raw(), parsedPrivate.Raw()) || !private.C.Equal(parsedPrivate.C) {
				t.Fatal("private key changed during PKCS #8 round trip")
			}
		})
	}
}

func TestGOSTKeyParsingRejectsAlgorithmCurveMismatchAndZeroScalar(t *testing.T) {
	curve := gost3410.CurveIdtc26gost341012256paramSetA()
	private, public := generateKey(t, curve)

	publicDER, err := MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	var publicInfo publicKeyInfoASN1
	if rest, err := asn1.Unmarshal(publicDER, &publicInfo); err != nil || len(rest) != 0 {
		t.Fatalf("decode public key: rest=%d err=%v", len(rest), err)
	}
	publicInfo.Raw = nil
	publicInfo.Algorithm.Algorithm = oidTc26Gost341012512
	mismatchedPublicDER, err := asn1.Marshal(publicInfo)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePKIXPublicKey(mismatchedPublicDER); err == nil {
		t.Fatal("512-bit algorithm OID with a 256-bit curve was accepted")
	}

	privateDER, err := MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	var privateInfo pkcs8
	if rest, err := asn1.Unmarshal(privateDER, &privateInfo); err != nil || len(rest) != 0 {
		t.Fatalf("decode private key: rest=%d err=%v", len(rest), err)
	}
	privateInfo.Algorithm.Algorithm = oidTc26Gost341012512
	mismatchedPrivateDER, err := asn1.Marshal(privateInfo)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePKCS8PrivateKey(mismatchedPrivateDER); err == nil {
		t.Fatal("512-bit algorithm OID with a 256-bit private-key curve was accepted")
	}

	if rest, err := asn1.Unmarshal(privateDER, &privateInfo); err != nil || len(rest) != 0 {
		t.Fatalf("decode private key again: rest=%d err=%v", len(rest), err)
	}
	// NewPrivateKey reduces the encoded scalar modulo Q. Encoding Q itself
	// therefore exercises the post-reduction zero check in the PKCS #8 parser.
	q := curve.Q.Bytes()
	rawQ := make([]byte, curve.PointSize())
	for i := range q {
		rawQ[i] = q[len(q)-1-i]
	}
	privateInfo.PrivateKey, err = asn1.Marshal(rawQ)
	if err != nil {
		t.Fatal(err)
	}
	zeroPrivateDER, err := asn1.Marshal(privateInfo)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePKCS8PrivateKey(zeroPrivateDER); err == nil {
		t.Fatal("private scalar congruent to zero modulo Q was accepted")
	}
}

func TestGOSTCertificateChain(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	rootPrivate, rootPublic := generateKey(t, gost3410.CurveIdtc26gost341012512paramSetA())
	rootTemplate := &Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "GOST Test Root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              KeyUsageDigitalSignature | KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	// A TLS-ready key wrapper must be normalized to the X.509 signature wire
	// format instead of reversing the certificate signature as TLS does.
	rootDER, err := CreateCertificate(
		rand.Reader, rootTemplate, rootTemplate, rootPublic,
		&gost3410.PrivateKeyReverseDigestAndSignature{Prv: rootPrivate},
	)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	if root.PublicKeyAlgorithm != GOST || root.SignatureAlgorithm != GOST512 {
		t.Fatalf("unexpected root algorithms: public=%v signature=%v", root.PublicKeyAlgorithm, root.SignatureAlgorithm)
	}
	var rawRoot struct {
		TBSCertificate struct {
			Version            int `asn1:"optional,explicit,default:0,tag:0"`
			SerialNumber       *big.Int
			SignatureAlgorithm asn1.RawValue
		}
	}
	if rest, err := asn1.Unmarshal(rootDER, &rawRoot); err != nil || len(rest) != 0 {
		t.Fatalf("decode root signature algorithm: rest=%d err=%v", len(rest), err)
	}
	wantRawSignatureAlgorithm := rawRoot.TBSCertificate.SignatureAlgorithm.FullBytes
	if !bytes.Equal(root.RawSignatureAlgorithm, wantRawSignatureAlgorithm) {
		t.Fatalf("RawSignatureAlgorithm = %x, want %x", root.RawSignatureAlgorithm, wantRawSignatureAlgorithm)
	}
	var rootSPKI publicKeyInfoASN1
	if rest, err := asn1.Unmarshal(root.RawSubjectPublicKeyInfo, &rootSPKI); err != nil || len(rest) != 0 {
		t.Fatalf("decode root SubjectPublicKeyInfo: rest=%d err=%v", len(rest), err)
	}
	wantSKID := sha1.Sum(rootSPKI.PublicKey.RightAlign())
	if !bytes.Equal(root.SubjectKeyId, wantSKID[:]) {
		t.Fatalf("root subject key identifier is not derived from the GOST public key")
	}
	if err := root.CheckSignature(root.SignatureAlgorithm, root.RawTBSCertificate, root.Signature); err != nil {
		t.Fatalf("self-signature: %v", err)
	}

	_, leafPublic := generateKey(t, gost3410.CurveIdtc26gost341012256paramSetB())
	leafTemplate := &Certificate{
		SerialNumber: big.NewInt(101),
		Subject:      pkix.Name{CommonName: "service.test"},
		DNSNames:     []string{"service.test"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     KeyUsageDigitalSignature,
		ExtKeyUsage:  []ExtKeyUsage{ExtKeyUsageServerAuth},
	}
	leafDER, err := CreateCertificate(rand.Reader, leafTemplate, root, leafPublic, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.SignatureAlgorithm != GOST512 {
		t.Fatalf("leaf signature algorithm = %v, want GOST512", leaf.SignatureAlgorithm)
	}
	if !bytes.Equal(leaf.AuthorityKeyId, root.SubjectKeyId) {
		t.Fatal("leaf authority key identifier does not match the GOST issuer")
	}
	if err := leaf.CheckSignatureFrom(root); err != nil {
		t.Fatalf("leaf signature: %v", err)
	}

	roots := NewCertPool()
	roots.AddCert(root)
	chains, err := leaf.Verify(VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		DNSName:     "service.test",
		KeyUsages:   []ExtKeyUsage{ExtKeyUsageServerAuth},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(chains) != 1 || len(chains[0]) != 2 || !chains[0][1].Equal(root) {
		t.Fatalf("unexpected chains: %#v", chains)
	}
	if _, err := leaf.Verify(VerifyOptions{Roots: roots, CurrentTime: now, DNSName: "other.test"}); err == nil {
		t.Fatal("hostname mismatch was accepted")
	}

	// Requested usages are alternatives, but one alternative must remain
	// valid through the entire chain. Leaf=server and root=client must not be
	// accepted merely because each certificate permits a different usage.
	root.ExtKeyUsage = []ExtKeyUsage{ExtKeyUsageClientAuth}
	if _, err := leaf.Verify(VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []ExtKeyUsage{ExtKeyUsageServerAuth, ExtKeyUsageClientAuth},
	}); err == nil {
		t.Fatal("disjoint extended key usages across the chain were accepted")
	}
}

func TestGOSTNameConstraintsApplyToIntermediatesAndBoundWork(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	rootPrivate, rootPublic := generateKey(t, gost3410.CurveIdtc26gost341012512paramSetA())
	rootTemplate := &Certificate{
		SerialNumber:                big.NewInt(200),
		Subject:                     pkix.Name{CommonName: "Constrained GOST Root"},
		NotBefore:                   now.Add(-time.Hour),
		NotAfter:                    now.Add(time.Hour),
		KeyUsage:                    KeyUsageCertSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         []string{"allowed.test"},
	}
	rootDER, err := CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPublic, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	intermediatePrivate, intermediatePublic := generateKey(t, gost3410.CurveIdtc26gost341012256paramSetB())
	intermediateTemplate := &Certificate{
		SerialNumber:          big.NewInt(201),
		Subject:               pkix.Name{CommonName: "Constrained GOST Intermediate"},
		DNSNames:              []string{"ca.allowed.test"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	intermediateDER, err := CreateCertificate(
		rand.Reader, intermediateTemplate, root, intermediatePublic, rootPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := ParseCertificate(intermediateDER)
	if err != nil {
		t.Fatal(err)
	}

	_, leafPublic := generateKey(t, gost3410.CurveIdtc26gost341012256paramSetA())
	leafTemplate := &Certificate{
		SerialNumber: big.NewInt(202),
		Subject:      pkix.Name{CommonName: "service.allowed.test"},
		DNSNames:     []string{"service.allowed.test"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     KeyUsageDigitalSignature,
		ExtKeyUsage:  []ExtKeyUsage{ExtKeyUsageServerAuth},
	}
	leafDER, err := CreateCertificate(
		rand.Reader, leafTemplate, intermediate, leafPublic, intermediatePrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	roots := NewCertPool()
	roots.AddCert(root)
	intermediates := NewCertPool()
	intermediates.AddCert(intermediate)
	opts := VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		DNSName:       "service.allowed.test",
		KeyUsages:     []ExtKeyUsage{ExtKeyUsageServerAuth},
	}
	if _, err := leaf.Verify(opts); err != nil {
		t.Fatalf("valid constrained chain: %v", err)
	}

	intermediate.DNSNames = []string{"ca.blocked.test"}
	if _, err := leaf.Verify(opts); err == nil {
		t.Fatal("root name constraints were not applied to an intermediate")
	}
	intermediate.DNSNames = []string{"ca.allowed.test"}

	opts.MaxConstraintComparisions = 1
	_, err = leaf.Verify(opts)
	var invalid CertificateInvalidError
	if !errors.As(err, &invalid) || invalid.Reason != TooManyConstraints {
		t.Fatalf("constraint comparison limit: got %v", err)
	}
}

func TestGOSTChainSignatureChecksAreBounded(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	private, public := generateKey(t, gost3410.CurveIdtc26gost341012256paramSetA())
	template := &Certificate{
		SerialNumber: big.NewInt(300),
		Subject:      pkix.Name{CommonName: "Signature Limit Leaf"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     KeyUsageDigitalSignature,
		ExtKeyUsage:  []ExtKeyUsage{ExtKeyUsageServerAuth},
	}
	der, err := CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	intermediates := NewCertPool()
	for index := 0; index <= maxChainSignatureChecks; index++ {
		candidate := *leaf
		candidate.Raw = []byte{byte(index), byte(index >> 8)}
		candidate.RawSubject = append([]byte(nil), leaf.RawIssuer...)
		candidate.BasicConstraintsValid = true
		candidate.IsCA = true
		candidate.KeyUsage = KeyUsageCertSign
		candidate.PublicKeyAlgorithm = GOST
		candidate.PublicKey = nil // Make every bounded signature attempt fail.
		intermediates.AddCert(&candidate)
	}

	_, err = leaf.Verify(VerifyOptions{
		Roots:         NewCertPool(),
		Intermediates: intermediates,
		CurrentTime:   now,
	})
	if !errors.Is(err, errSignatureLimit) {
		t.Fatalf("signature check limit: got %v", err)
	}
}
