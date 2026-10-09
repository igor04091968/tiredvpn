package gostx509

import (
	"crypto/elliptic"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"gitverse.ru/uzer_007/gogost/v3/gost3410"
)

var (
	oidPublicKeyECDSA                     = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidNamedCurveP256                     = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidSignatureECDSAWithSHA256           = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidTc26Gost341012256                  = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 1}
	oidTc26Gost341012512                  = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 2}
	oidTc26Gost34112012256                = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 2}
	oidTc26Gost34112012512                = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 3}
	oidTc26Gost341012256Signature         = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 3, 2}
	oidTc26Gost341012512Signature         = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 3, 3}
	oidGostR34102001CryptoProAParamSet    = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 1}
	oidGostR34102001CryptoProBParamSet    = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 2}
	oidGostR34102001CryptoProCParamSet    = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 3}
	oidGostR34102001CryptoProXchAParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 36, 0}
	oidGostR34102001CryptoProXchBParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 36, 1}
	oidTc26Gost341012256ParamSetA         = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1}
	oidTc26Gost341012256ParamSetB         = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 2}
	oidTc26Gost341012256ParamSetC         = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 3}
	oidTc26Gost341012256ParamSetD         = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 4}
	oidTc26Gost341012512ParamSetA         = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 1}
	oidTc26Gost341012512ParamSetB         = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 2}
	oidTc26Gost341012512ParamSetC         = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 3}
)

// GostR341012PublicKeyParameters is the AlgorithmIdentifier parameter
// sequence used by GOST R 34.10-2012 SubjectPublicKeyInfo values.
type GostR341012PublicKeyParameters struct {
	PublicKeyParamSet  asn1.ObjectIdentifier
	DigestParamSet     asn1.ObjectIdentifier `asn1:"optional"`
	EncryptionParamSet asn1.ObjectIdentifier `asn1:"optional"`
}

type certificateASN1 struct {
	TBSCertificate     tbsCertificateASN1
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type tbsCertificateASN1 struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validityASN1
	Subject            asn1.RawValue
	PublicKey          publicKeyInfoASN1
	UniqueID           asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueID    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"omitempty,optional,explicit,tag:3"`
}

type validityASN1 struct {
	NotBefore, NotAfter time.Time
}

type publicKeyInfoASN1 struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func isGOSTPublicKeyOID(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(oidGostR34102001) || oid.Equal(oidTc26Gost341012256) || oid.Equal(oidTc26Gost341012512)
}

func validateGOSTAlgorithmCurve(algorithm asn1.ObjectIdentifier, curve *gost3410.Curve) error {
	if curve == nil {
		return errors.New("gostx509: missing GOST curve")
	}
	wantSize := 0
	switch {
	case algorithm.Equal(oidGostR34102001):
		wantSize = 32
	case algorithm.Equal(oidTc26Gost341012256):
		wantSize = 32
	case algorithm.Equal(oidTc26Gost341012512):
		wantSize = 64
	default:
		return fmt.Errorf("gostx509: unsupported GOST public-key algorithm %v", algorithm)
	}
	if curve.PointSize() != wantSize {
		return errors.New("gostx509: GOST public-key algorithm and curve sizes do not match")
	}
	return nil
}

func gostSignatureAlgorithm(oid asn1.ObjectIdentifier) SignatureAlgorithm {
	switch {
	case oid.Equal(oidGostR34112001WithR34102001):
		return GOST2001
	case oid.Equal(oidTc26Gost341012256Signature):
		return GOST256
	case oid.Equal(oidTc26Gost341012512Signature):
		return GOST512
	default:
		return UnknownSignatureAlgorithm
	}
}

func curveForOID(oid asn1.ObjectIdentifier) (*gost3410.Curve, error) {
	switch {
	case oid.Equal(oidGostR34102001CryptoProAParamSet):
		return gost3410.CurveIdGostR34102001CryptoProAParamSet(), nil
	case oid.Equal(oidGostR34102001CryptoProBParamSet):
		return gost3410.CurveIdGostR34102001CryptoProBParamSet(), nil
	case oid.Equal(oidGostR34102001CryptoProCParamSet):
		return gost3410.CurveIdGostR34102001CryptoProCParamSet(), nil
	case oid.Equal(oidGostR34102001CryptoProXchAParamSet):
		return gost3410.CurveIdGostR34102001CryptoProXchAParamSet(), nil
	case oid.Equal(oidGostR34102001CryptoProXchBParamSet):
		return gost3410.CurveIdGostR34102001CryptoProXchBParamSet(), nil
	case oid.Equal(oidTc26Gost341012256ParamSetA):
		return gost3410.CurveIdtc26gost34102012256paramSetA(), nil
	case oid.Equal(oidTc26Gost341012256ParamSetB):
		return gost3410.CurveIdtc26gost34102012256paramSetB(), nil
	case oid.Equal(oidTc26Gost341012256ParamSetC):
		return gost3410.CurveIdtc26gost34102012256paramSetC(), nil
	case oid.Equal(oidTc26Gost341012256ParamSetD):
		return gost3410.CurveIdtc26gost34102012256paramSetD(), nil
	case oid.Equal(oidTc26Gost341012512ParamSetA):
		return gost3410.CurveIdtc26gost34102012512paramSetA(), nil
	case oid.Equal(oidTc26Gost341012512ParamSetB):
		return gost3410.CurveIdtc26gost34102012512paramSetB(), nil
	case oid.Equal(oidTc26Gost341012512ParamSetC):
		return gost3410.CurveIdtc26gost34102012512paramSetC(), nil
	case oid.Equal(oidTc26Gost341012512ParamSetT):
		return gost3410.CurveIdtc26gost34102012512paramSetTest(), nil
	default:
		return nil, fmt.Errorf("gostx509: unknown GOST curve OID %v", oid)
	}
}

func oidForCurve(curve *gost3410.Curve) (keyOID, curveOID asn1.ObjectIdentifier, err error) {
	switch curve.Name {
	case "id-GostR3410-2001-CryptoPro-A-ParamSet":
		return oidGostR34102001, oidGostR34102001CryptoProAParamSet, nil
	case "id-GostR3410-2001-CryptoPro-B-ParamSet":
		return oidGostR34102001, oidGostR34102001CryptoProBParamSet, nil
	case "id-GostR3410-2001-CryptoPro-C-ParamSet":
		return oidGostR34102001, oidGostR34102001CryptoProCParamSet, nil
	case "id-GostR3410-2001-CryptoPro-XchA-ParamSet":
		return oidGostR34102001, oidGostR34102001CryptoProXchAParamSet, nil
	case "id-GostR3410-2001-CryptoPro-XchB-ParamSet":
		return oidGostR34102001, oidGostR34102001CryptoProXchBParamSet, nil
	case "id-tc26-gost-3410-12-256-paramSetA", "id-tc26-gost-3410-2012-256-paramSetA":
		return oidTc26Gost341012256, oidTc26Gost341012256ParamSetA, nil
	case "id-tc26-gost-3410-12-256-paramSetB", "id-tc26-gost-3410-2012-256-paramSetB":
		return oidTc26Gost341012256, oidTc26Gost341012256ParamSetB, nil
	case "id-tc26-gost-3410-12-256-paramSetC", "id-tc26-gost-3410-2012-256-paramSetC":
		return oidTc26Gost341012256, oidTc26Gost341012256ParamSetC, nil
	case "id-tc26-gost-3410-12-256-paramSetD", "id-tc26-gost-3410-2012-256-paramSetD":
		return oidTc26Gost341012256, oidTc26Gost341012256ParamSetD, nil
	case "id-tc26-gost-3410-12-512-paramSetA", "id-tc26-gost-3410-2012-512-paramSetA":
		return oidTc26Gost341012512, oidTc26Gost341012512ParamSetA, nil
	case "id-tc26-gost-3410-12-512-paramSetB", "id-tc26-gost-3410-2012-512-paramSetB":
		return oidTc26Gost341012512, oidTc26Gost341012512ParamSetB, nil
	case "id-tc26-gost-3410-12-512-paramSetC", "id-tc26-gost-3410-2012-512-paramSetC":
		return oidTc26Gost341012512, oidTc26Gost341012512ParamSetC, nil
	case "id-tc26-gost-3410-12-512-paramSetTest", "id-tc26-gost-3410-2012-512-paramSetTest":
		return oidTc26Gost341012512, oidTc26Gost341012512ParamSetT, nil
	default:
		return nil, nil, fmt.Errorf("gostx509: unsupported GOST curve %q", curve.Name)
	}
}

func validateGOSTPublicKey(pub *gost3410.PublicKey) error {
	if err := pub.Validate(); err != nil {
		return fmt.Errorf("gostx509: invalid GOST public key: %w", err)
	}
	return nil
}

func parseGOSTPublicKey(info *publicKeyInfoASN1) (*gost3410.PublicKey, error) {
	if !isGOSTPublicKeyOID(info.Algorithm.Algorithm) {
		return nil, errors.New("gostx509: SubjectPublicKeyInfo is not a GOST key")
	}
	var params GostR341012PublicKeyParameters
	rest, err := asn1.Unmarshal(info.Algorithm.Parameters.FullBytes, &params)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("gostx509: malformed GOST public-key parameters")
	}
	curve, err := curveForOID(params.PublicKeyParamSet)
	if err != nil {
		return nil, err
	}
	if err := validateGOSTAlgorithmCurve(info.Algorithm.Algorithm, curve); err != nil {
		return nil, err
	}
	var raw []byte
	rest, err = asn1.Unmarshal(info.PublicKey.RightAlign(), &raw)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("gostx509: malformed GOST public key")
	}
	pub, err := gost3410.NewPublicKey(curve, raw)
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// ParseCertificate разбирает один DER-сертификат X.509, включая ключи и
// подписи ГОСТ Р 34.10-2001 и ГОСТ Р 34.10-2012.
func ParseCertificate(der []byte) (*Certificate, error) {
	var original certificateASN1
	parsedGOST := false
	if fast, ok := parseCertificateASN1Fast(der); ok && isGOSTPublicKeyOID(fast.TBSCertificate.SubjectPublicKeyInfo.Algorithm.Algorithm) {
		original = fullCertificateFromInfoASN1(fast)
		parsedGOST = true
	}
	if !parsedGOST {
		if cert, err := stdx509.ParseCertificate(der); err == nil && cert.PublicKey != nil {
			return fromStandard(cert), nil
		}
		rest, err := asn1.Unmarshal(der, &original)
		if err != nil || len(rest) != 0 {
			return nil, errors.New("gostx509: malformed certificate")
		}
	}
	if !isGOSTPublicKeyOID(original.TBSCertificate.PublicKey.Algorithm.Algorithm) {
		return nil, errors.New("gostx509: unsupported certificate public-key algorithm")
	}
	pub, err := parseGOSTPublicKey(&original.TBSCertificate.PublicKey)
	if err != nil {
		return nil, err
	}
	sigAlgo := gostSignatureAlgorithm(original.SignatureAlgorithm.Algorithm)
	if sigAlgo == UnknownSignatureAlgorithm {
		return nil, fmt.Errorf("gostx509: unsupported GOST signature OID %v", original.SignatureAlgorithm.Algorithm)
	}
	if inner := gostSignatureAlgorithm(original.TBSCertificate.SignatureAlgorithm.Algorithm); inner != sigAlgo {
		return nil, errors.New("gostx509: inner and outer signature algorithms do not match")
	}
	rawSignatureAlgorithm, ok := rawTBSCertificateSignatureAlgorithm(original.TBSCertificate.Raw)
	if !ok {
		return nil, errors.New("gostx509: malformed certificate signature algorithm")
	}

	originalTBS := append([]byte(nil), original.TBSCertificate.Raw...)
	originalSPKI := append([]byte(nil), original.TBSCertificate.PublicKey.Raw...)
	originalSig := append([]byte(nil), original.SignatureValue.RightAlign()...)

	// Keep the original names, validity and extensions byte-for-byte while
	// substituting only algorithms unknown to crypto/x509. Its mature metadata
	// parser still validates the reconstructed certificate.
	dummyDER, err := certificateParserDummyDER(original.TBSCertificate.Raw)
	if err != nil {
		return nil, fmt.Errorf("gostx509: failed to construct parser input: %w", err)
	}
	parsed, err := stdx509.ParseCertificate(dummyDER)
	if err != nil {
		return nil, fmt.Errorf("gostx509: failed to parse certificate fields: %w", err)
	}
	parsed.Raw = append([]byte(nil), der...)
	parsed.RawTBSCertificate = originalTBS
	parsed.RawSubjectPublicKeyInfo = originalSPKI
	parsed.RawSignatureAlgorithm = rawSignatureAlgorithm
	parsed.Signature = originalSig
	parsed.SignatureAlgorithm = sigAlgo
	parsed.PublicKeyAlgorithm = GOST
	parsed.PublicKey = pub
	return fromStandard(parsed), nil
}

func rawTBSCertificateSignatureAlgorithm(der []byte) ([]byte, bool) {
	tag, sequence, rest, ok := readDERElement(der)
	if !ok || tag != 0x30 || len(rest) != 0 {
		return nil, false
	}
	if len(sequence) > 0 && sequence[0] == 0xa0 { // optional explicit version
		_, _, sequence, ok = readDERElement(sequence)
		if !ok {
			return nil, false
		}
	}
	tag, _, sequence, ok = readDERElement(sequence) // serial number
	if !ok || tag != 0x02 {
		return nil, false
	}
	tag, full, _, _, ok := readDERElementFull(sequence)
	if !ok || tag != 0x30 {
		return nil, false
	}
	return append([]byte(nil), full...), true
}

func fullCertificateFromInfoASN1(info certificateInfoASN1) certificateASN1 {
	algorithm := func(value algorithmIdentifierASN1) pkix.AlgorithmIdentifier {
		return pkix.AlgorithmIdentifier{Algorithm: value.Algorithm, Parameters: value.Parameters}
	}
	tbs := info.TBSCertificate
	return certificateASN1{
		TBSCertificate: tbsCertificateASN1{
			Raw: tbs.Raw, Version: tbs.Version, SerialNumber: tbs.SerialNumber,
			SignatureAlgorithm: algorithm(tbs.Signature), Issuer: tbs.Issuer,
			Validity: validityASN1{NotBefore: tbs.Validity.NotBefore, NotAfter: tbs.Validity.NotAfter},
			Subject:  tbs.Subject,
			PublicKey: publicKeyInfoASN1{
				Raw:       tbs.SubjectPublicKeyInfo.Raw,
				Algorithm: algorithm(tbs.SubjectPublicKeyInfo.Algorithm),
				PublicKey: tbs.SubjectPublicKeyInfo.SubjectPublicKey,
			},
			UniqueID: tbs.IssuerUniqueID, SubjectUniqueID: tbs.SubjectUniqueID,
			Extensions: tbs.Extensions,
		},
		SignatureAlgorithm: algorithm(info.SignatureAlgorithm),
		SignatureValue:     info.SignatureValue,
	}
}

// ParseCertificates parses one or more concatenated DER certificates.
func ParseCertificates(der []byte) ([]*Certificate, error) {
	var result []*Certificate
	for len(der) > 0 {
		var raw asn1.RawValue
		rest, err := asn1.Unmarshal(der, &raw)
		if err != nil || len(raw.FullBytes) == 0 {
			return nil, errors.New("gostx509: malformed certificate sequence")
		}
		cert, err := ParseCertificate(raw.FullBytes)
		if err != nil {
			return nil, err
		}
		result = append(result, cert)
		der = rest
	}
	return result, nil
}

// ParsePKIXPublicKey parses a DER SubjectPublicKeyInfo value.
func ParsePKIXPublicKey(der []byte) (any, error) {
	if key, err := stdx509.ParsePKIXPublicKey(der); err == nil {
		return key, nil
	}
	var info publicKeyInfoASN1
	rest, err := asn1.Unmarshal(der, &info)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("gostx509: malformed SubjectPublicKeyInfo")
	}
	return parseGOSTPublicKey(&info)
}

// MarshalPKIXPublicKey marshals a public key as SubjectPublicKeyInfo.
func MarshalPKIXPublicKey(pub any) ([]byte, error) {
	gostPub, ok := pub.(*gost3410.PublicKey)
	if !ok {
		return stdx509.MarshalPKIXPublicKey(pub)
	}
	if err := validateGOSTPublicKey(gostPub); err != nil {
		return nil, err
	}
	algorithm, err := gostAlgorithmIdentifier(gostPub)
	if err != nil {
		return nil, err
	}
	keyDER, err := asn1.Marshal(gostPub.Raw())
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(publicKeyInfoASN1{
		Algorithm: algorithm,
		PublicKey: asn1.BitString{Bytes: keyDER, BitLength: 8 * len(keyDER)},
	})
}

// ParseCertificateRequest parses PKCS #10 requests signed with GOST or the
// algorithms supported by crypto/x509.
func ParseCertificateRequest(der []byte) (*CertificateRequest, error) {
	if req, err := stdx509.ParseCertificateRequest(der); err == nil && req.PublicKey != nil && req.SignatureAlgorithm != stdx509.UnknownSignatureAlgorithm {
		return (*CertificateRequest)(req), nil
	}
	var original certificationRequestASN1
	if rest, err := asn1.Unmarshal(der, &original); err != nil || len(rest) != 0 {
		return nil, errors.New("gostx509: Некорректный запрос сертификата")
	}
	pub, err := parseGOSTPublicKey(&original.Info.PublicKey)
	if err != nil {
		return nil, err
	}
	signatureAlgorithm := gostSignatureAlgorithm(original.SignatureAlgorithm.Algorithm)
	if signatureAlgorithm == UnknownSignatureAlgorithm {
		return nil, ErrUnsupportedAlgorithm
	}
	originalInfo := append([]byte(nil), original.Info.Raw...)
	originalSPKI := append([]byte(nil), original.Info.PublicKey.Raw...)
	originalSignature := append([]byte(nil), original.SignatureValue.RightAlign()...)
	paramsDER, _ := asn1.Marshal(oidNamedCurveP256)
	original.Info.Raw = nil
	original.Info.PublicKey.Raw = nil
	original.Info.PublicKey.Algorithm = pkix.AlgorithmIdentifier{
		Algorithm: oidPublicKeyECDSA, Parameters: asn1.RawValue{FullBytes: paramsDER},
	}
	dummyPoint := elliptic.Marshal(elliptic.P256(), elliptic.P256().Params().Gx, elliptic.P256().Params().Gy)
	original.Info.PublicKey.PublicKey = asn1.BitString{Bytes: dummyPoint, BitLength: 8 * len(dummyPoint)}
	original.SignatureAlgorithm = pkix.AlgorithmIdentifier{Algorithm: oidSignatureECDSAWithSHA256}
	dummySignature, _ := asn1.Marshal(struct{ R, S *big.Int }{big.NewInt(1), big.NewInt(1)})
	original.SignatureValue = asn1.BitString{Bytes: dummySignature, BitLength: 8 * len(dummySignature)}
	dummyDER, err := asn1.Marshal(original)
	if err != nil {
		return nil, err
	}
	parsed, err := stdx509.ParseCertificateRequest(dummyDER)
	if err != nil {
		return nil, err
	}
	parsed.Raw = append([]byte(nil), der...)
	parsed.RawTBSCertificateRequest = originalInfo
	parsed.RawSubjectPublicKeyInfo = originalSPKI
	parsed.Signature = originalSignature
	parsed.SignatureAlgorithm = signatureAlgorithm
	parsed.PublicKeyAlgorithm = GOST
	parsed.PublicKey = pub
	return (*CertificateRequest)(parsed), nil
}

// CheckSignature verifies the request signature, independent of any trust in
// the requested subject name.
func (r *CertificateRequest) CheckSignature() error {
	if r == nil {
		return errors.New("gostx509: Пустой запрос сертификата")
	}
	if r.SignatureAlgorithm != GOST2001 && r.SignatureAlgorithm != GOST256 && r.SignatureAlgorithm != GOST512 {
		return (*stdx509.CertificateRequest)(r).CheckSignature()
	}
	cert := &Certificate{PublicKeyAlgorithm: r.PublicKeyAlgorithm, PublicKey: r.PublicKey}
	return cert.CheckSignature(r.SignatureAlgorithm, r.RawTBSCertificateRequest, r.Signature)
}
