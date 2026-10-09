package gostx509

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha1"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"

	"gitverse.ru/uzer_007/gogost/v3/gost28147"
	"gitverse.ru/uzer_007/gogost/v3/gost3410"
	"gitverse.ru/uzer_007/gogost/v3/gost34112012256"
	"gitverse.ru/uzer_007/gogost/v3/gost34112012512"
	"gitverse.ru/uzer_007/gogost/v3/gost341194"
)

type gostSignerOpts struct{}

func (gostSignerOpts) HashFunc() crypto.Hash { return crypto.Hash(0) }

func gostPrivateKey(key any) (*gost3410.PrivateKey, crypto.Signer, bool) {
	switch k := key.(type) {
	case *gost3410.PrivateKey:
		return k, &gost3410.PrivateKeyReverseDigest{Prv: k}, true
	case *gost3410.PrivateKeyReverseDigest:
		return k.Prv, k, true
	case *gost3410.PrivateKeyReverseDigestAndSignature:
		// Certificate signatures reverse the Streebog digest, but unlike the
		// RFC 9367 CertificateVerify value they do not reverse the signature.
		return k.Prv, &gost3410.PrivateKeyReverseDigest{Prv: k.Prv}, true
	default:
		return nil, nil, false
	}
}

func gostPublicKey(key any) (*gost3410.PublicKey, bool) {
	switch k := key.(type) {
	case *gost3410.PublicKey:
		return k, true
	case *gost3410.PrivateKey:
		pub, err := k.PublicKey()
		return pub, err == nil
	default:
		return nil, false
	}
}

func gostAlgorithmIdentifier(pub *gost3410.PublicKey) (pkix.AlgorithmIdentifier, error) {
	keyOID, curveOID, err := oidForCurve(pub.C)
	if err != nil {
		return pkix.AlgorithmIdentifier{}, err
	}
	params := GostR341012PublicKeyParameters{PublicKeyParamSet: curveOID}
	// Legacy CryptoPro parameter sets conventionally include the digest OID;
	// the TC26 parameter sets leave it absent.
	if strings.HasPrefix(pub.C.Name, "id-GostR3410-2001-") {
		params.DigestParamSet = oidGostR341194CryptoProParamSet
	}
	paramsDER, err := asn1.Marshal(params)
	if err != nil {
		return pkix.AlgorithmIdentifier{}, err
	}
	return pkix.AlgorithmIdentifier{
		Algorithm:  keyOID,
		Parameters: asn1.RawValue{FullBytes: paramsDER},
	}, nil
}

func gostCertificateSignatureAlgorithm(curve *gost3410.Curve) (SignatureAlgorithm, pkix.AlgorithmIdentifier, error) {
	if strings.HasPrefix(curve.Name, "id-GostR3410-2001-") {
		return GOST2001, pkix.AlgorithmIdentifier{Algorithm: oidGostR34112001WithR34102001}, nil
	}
	switch curve.PointSize() {
	case 32:
		return GOST256, pkix.AlgorithmIdentifier{Algorithm: oidTc26Gost341012256Signature}, nil
	case 64:
		return GOST512, pkix.AlgorithmIdentifier{Algorithm: oidTc26Gost341012512Signature}, nil
	default:
		return 0, pkix.AlgorithmIdentifier{}, fmt.Errorf("gostx509: unsupported GOST key size %d", curve.PointSize())
	}
}

func hashCertificate(algo SignatureAlgorithm, signed []byte) ([]byte, error) {
	switch algo {
	case GOST2001:
		h := gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
		_, _ = h.Write(signed)
		return h.Sum(nil), nil
	case GOST256:
		h := gost34112012256.New()
		_, _ = h.Write(signed)
		return h.Sum(nil), nil
	case GOST512:
		h := gost34112012512.New()
		_, _ = h.Write(signed)
		return h.Sum(nil), nil
	default:
		return nil, ErrUnsupportedAlgorithm
	}
}

func fixedECDSAKey() *ecdsa.PrivateKey {
	curve := elliptic.P256()
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: new(big.Int).Set(curve.Params().Gx), Y: new(big.Int).Set(curve.Params().Gy)},
		D:         big.NewInt(1),
	}
}

// CreateCertificate creates an X.509 certificate. For GOST public keys it
// emits the TC26 SubjectPublicKeyInfo and signs the TBSCertificate using GOST
// R 34.10-2012 and the matching Streebog digest.
func CreateCertificate(rand io.Reader, template, parent *Certificate, pub, priv any) ([]byte, error) {
	gostPub, isGOST := gostPublicKey(pub)
	issuerPrivate, signer, issuerIsGOST := gostPrivateKey(priv)
	if !isGOST && !issuerIsGOST {
		return stdx509.CreateCertificate(rand, asStandard(template), asStandard(parent), pub, priv)
	}
	if !isGOST || !issuerIsGOST {
		return nil, errors.New("gostx509: GOST certificate creation requires GOST subject and issuer keys")
	}
	if err := validateGOSTPublicKey(gostPub); err != nil {
		return nil, err
	}
	publicKeyAlgorithm, err := gostAlgorithmIdentifier(gostPub)
	if err != nil {
		return nil, err
	}
	publicKeyDER, err := asn1.Marshal(gostPub.Raw())
	if err != nil {
		return nil, err
	}

	// crypto/x509 remains responsible for encoding names, validity and
	// extensions. A temporary ECDSA certificate is then rewritten and signed
	// with the requested GOST algorithms.
	dummy := fixedECDSAKey()
	stdTemplate := *asStandard(template)
	stdParent := *asStandard(parent)
	if stdTemplate.IsCA && len(stdTemplate.SubjectKeyId) == 0 {
		// Match crypto/x509's default SKID rule, but hash the actual contents
		// of the GOST subjectPublicKey BIT STRING rather than the temporary
		// ECDSA key used only to encode the surrounding certificate fields.
		skid := sha1.Sum(publicKeyDER)
		stdTemplate.SubjectKeyId = skid[:]
	}
	stdTemplate.SignatureAlgorithm = stdx509.ECDSAWithSHA256
	stdTemplate.PublicKeyAlgorithm = stdx509.ECDSA
	stdTemplate.PublicKey = &dummy.PublicKey
	stdParent.SignatureAlgorithm = stdx509.ECDSAWithSHA256
	stdParent.PublicKeyAlgorithm = stdx509.ECDSA
	stdParent.PublicKey = &dummy.PublicKey
	dummyDER, err := stdx509.CreateCertificate(rand, &stdTemplate, &stdParent, &dummy.PublicKey, dummy)
	if err != nil {
		return nil, fmt.Errorf("gostx509: failed to encode certificate fields: %w", err)
	}

	var cert certificateASN1
	rest, err := asn1.Unmarshal(dummyDER, &cert)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("gostx509: internal certificate encoding failure")
	}
	_, signatureAlgorithm, err := gostCertificateSignatureAlgorithm(issuerPrivate.C)
	if err != nil {
		return nil, err
	}
	cert.TBSCertificate.Raw = nil
	cert.TBSCertificate.PublicKey.Raw = nil
	cert.TBSCertificate.PublicKey.Algorithm = publicKeyAlgorithm
	cert.TBSCertificate.PublicKey.PublicKey = asn1.BitString{
		Bytes: publicKeyDER, BitLength: 8 * len(publicKeyDER),
	}
	cert.TBSCertificate.SignatureAlgorithm = signatureAlgorithm
	cert.SignatureAlgorithm = signatureAlgorithm

	tbsDER, err := asn1.Marshal(cert.TBSCertificate)
	if err != nil {
		return nil, fmt.Errorf("gostx509: failed to marshal TBSCertificate: %w", err)
	}
	sigKind, _, _ := gostCertificateSignatureAlgorithm(issuerPrivate.C)
	digest, err := hashCertificate(sigKind, tbsDER)
	if err != nil {
		return nil, err
	}
	signature, err := signer.Sign(rand, digest, gostSignerOpts{})
	if err != nil {
		return nil, fmt.Errorf("gostx509: signing failed: %w", err)
	}
	cert.SignatureValue = asn1.BitString{Bytes: signature, BitLength: 8 * len(signature)}
	return asn1.Marshal(cert)
}

type certificationRequestASN1 struct {
	Info               certificationRequestInfoASN1
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type certificationRequestInfoASN1 struct {
	Raw        asn1.RawContent
	Version    int
	Subject    asn1.RawValue
	PublicKey  publicKeyInfoASN1
	Attributes asn1.RawValue
}

// CreateCertificateRequest creates a PKCS #10 request, including GOST keys.
func CreateCertificateRequest(rand io.Reader, template *CertificateRequest, priv any) ([]byte, error) {
	if template == nil {
		return nil, errors.New("gostx509: Пустой шаблон запроса")
	}
	private, signer, isGOST := gostPrivateKey(priv)
	if !isGOST {
		return stdx509.CreateCertificateRequest(rand, (*stdx509.CertificateRequest)(template), priv)
	}
	pub, err := private.PublicKey()
	if err != nil {
		return nil, err
	}
	if err = validateGOSTPublicKey(pub); err != nil {
		return nil, err
	}
	algorithm, err := gostAlgorithmIdentifier(pub)
	if err != nil {
		return nil, err
	}
	keyDER, err := asn1.Marshal(pub.Raw())
	if err != nil {
		return nil, err
	}
	dummy := fixedECDSAKey()
	stdTemplate := *(*stdx509.CertificateRequest)(template)
	stdTemplate.SignatureAlgorithm = stdx509.ECDSAWithSHA256
	dummyDER, err := stdx509.CreateCertificateRequest(rand, &stdTemplate, dummy)
	if err != nil {
		return nil, fmt.Errorf("gostx509: Ошибка кодирования запроса: %w", err)
	}
	var req certificationRequestASN1
	if rest, e := asn1.Unmarshal(dummyDER, &req); e != nil || len(rest) != 0 {
		return nil, errors.New("gostx509: Ошибка разбора подготовленного запроса")
	}
	_, signatureAlgorithm, err := gostCertificateSignatureAlgorithm(pub.C)
	if err != nil {
		return nil, err
	}
	req.Info.Raw = nil
	req.Info.PublicKey.Raw = nil
	req.Info.PublicKey.Algorithm = algorithm
	req.Info.PublicKey.PublicKey = asn1.BitString{Bytes: keyDER, BitLength: 8 * len(keyDER)}
	req.SignatureAlgorithm = signatureAlgorithm
	infoDER, err := asn1.Marshal(req.Info)
	if err != nil {
		return nil, err
	}
	signatureKind, _, _ := gostCertificateSignatureAlgorithm(pub.C)
	digest, err := hashCertificate(signatureKind, infoDER)
	if err != nil {
		return nil, err
	}
	signature, err := signer.Sign(rand, digest, gostSignerOpts{})
	if err != nil {
		return nil, err
	}
	req.SignatureValue = asn1.BitString{Bytes: signature, BitLength: 8 * len(signature)}
	return asn1.Marshal(req)
}
