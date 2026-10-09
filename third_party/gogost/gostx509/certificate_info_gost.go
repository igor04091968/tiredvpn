package gostx509

import (
	"bytes"
	"crypto/subtle"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"hash"
	"time"

	"gitverse.ru/uzer_007/gogost/v3/gost28147"
	"gitverse.ru/uzer_007/gogost/v3/gost3410"
	"gitverse.ru/uzer_007/gogost/v3/gost34112012256"
	"gitverse.ru/uzer_007/gogost/v3/gost34112012512"
	"gitverse.ru/uzer_007/gogost/v3/gost341194"
)

const (
	GOSTAlgorithmUnknown       = ""
	GOSTAlgorithm34102001      = "gost3410-2001"
	GOSTAlgorithm34102012256   = "gost3410-2012-256"
	GOSTAlgorithm34102012512   = "gost3410-2012-512"
	GOSTDigestAlgorithm341194  = "gost3411-94"
	GOSTDigestAlgorithm2012256 = "gost3411-2012-256"
	GOSTDigestAlgorithm2012512 = "gost3411-2012-512"
)

var (
	oidGostR34102001                = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 19}
	oidGostR34112001WithR34102001   = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 3}
	oidGostR341194                  = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 9}
	oidGostR341194CryptoProParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 30, 1}
	oidTc26Gost341012512ParamSetT   = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 0}

	knownCertificateInfoGOSTOIDsByDER = makeKnownCertificateInfoGOSTOIDsByDER()
)

type gostPublicKeyInfoParameters struct {
	PublicKeyParamSet  asn1.ObjectIdentifier
	DigestParamSet     asn1.ObjectIdentifier `asn1:"optional"`
	EncryptionParamSet asn1.ObjectIdentifier `asn1:"optional"`
}

// GostPublicKeyInfo содержит разобранный SubjectPublicKeyInfo ГОСТ и
// нормализованные параметры алгоритма.
type GostPublicKeyInfo struct {
	Algorithm       string
	AlgorithmOID    string
	Curve           string
	CurveOID        string
	DigestAlgorithm string
	DigestOID       string
	PublicKeyRaw    []byte
	PublicKeyRawHex string
	PublicKey       *gost3410.PublicKey
}

func parseGostPublicKeyView(spki subjectPublicKeyInfoMetadataASN1) (*GostPublicKeyInfo, error) {
	algorithm, err := gostKeyAlgorithmName(spki.Algorithm.Algorithm)
	if err != nil {
		return nil, err
	}
	params, err := parseGostPublicKeyInfoParameters(spki.Algorithm.Parameters)
	if err != nil {
		return nil, err
	}
	curve, err := curveForOID(params.PublicKeyParamSet)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedCertificate, err)
	}
	if err := validateGOSTAlgorithmCurve(spki.Algorithm.Algorithm, curve); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedCertificate, err)
	}
	raw, err := gostPublicKeyBytesView(spki.SubjectPublicKey.Bytes, curve.PointSize())
	if err != nil {
		return nil, err
	}
	publicKey, err := gost3410.NewPublicKey(curve, raw)
	if err != nil {
		return nil, fmt.Errorf("%w: parse GOST public key: %v", ErrMalformedCertificate, err)
	}
	if err := validateGOSTPublicKey(publicKey); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedCertificate, err)
	}
	return &GostPublicKeyInfo{
		Algorithm:       algorithm,
		AlgorithmOID:    gostOIDString(spki.Algorithm.Algorithm),
		Curve:           curve.Name,
		CurveOID:        gostOIDString(params.PublicKeyParamSet),
		DigestAlgorithm: gostDigestName(params.DigestParamSet),
		DigestOID:       gostOIDString(params.DigestParamSet),
		PublicKeyRaw:    raw,
		PublicKeyRawHex: hex.EncodeToString(raw),
		PublicKey:       publicKey,
	}, nil
}

func parseGostPublicKeyInfoParameters(raw asn1.RawValue) (gostPublicKeyInfoParameters, error) {
	if len(raw.FullBytes) == 0 {
		return gostPublicKeyInfoParameters{}, fmt.Errorf("%w: GOST public key parameters are absent", ErrMalformedCertificate)
	}
	if params, ok := parseGostPublicKeyInfoParametersFast(raw.FullBytes); ok {
		return params, nil
	}
	var params gostPublicKeyInfoParameters
	rest, err := asn1.Unmarshal(raw.FullBytes, &params)
	if err != nil || len(rest) != 0 || len(params.PublicKeyParamSet) == 0 {
		return gostPublicKeyInfoParameters{}, fmt.Errorf("%w: malformed GOST public key parameters", ErrMalformedCertificate)
	}
	return params, nil
}

func parseGostPublicKeyInfoParametersFast(der []byte) (gostPublicKeyInfoParameters, bool) {
	tag, sequence, rest, ok := readDERElement(der)
	if !ok || tag != 0x30 || len(rest) != 0 {
		return gostPublicKeyInfoParameters{}, false
	}
	var params gostPublicKeyInfoParameters
	fields := [...]*asn1.ObjectIdentifier{&params.PublicKeyParamSet, &params.DigestParamSet, &params.EncryptionParamSet}
	for index := 0; len(sequence) != 0; index++ {
		if index == len(fields) {
			return gostPublicKeyInfoParameters{}, false
		}
		tag, oidDER, next, ok := readDERElement(sequence)
		if !ok || tag != 0x06 {
			return gostPublicKeyInfoParameters{}, false
		}
		oid, known := knownCertificateInfoGOSTOIDsByDER[string(oidDER)]
		if !known {
			return gostPublicKeyInfoParameters{}, false
		}
		*fields[index] = oid
		sequence = next
	}
	return params, len(params.PublicKeyParamSet) != 0
}

func makeKnownCertificateInfoGOSTOIDsByDER() map[string]asn1.ObjectIdentifier {
	oids := []asn1.ObjectIdentifier{
		oidGostR34102001, oidGostR34112001WithR34102001, oidGostR341194,
		oidGostR341194CryptoProParamSet, oidTc26Gost341012256,
		oidTc26Gost341012512, oidTc26Gost34112012256, oidTc26Gost34112012512,
		oidTc26Gost341012256Signature, oidTc26Gost341012512Signature,
		oidGostR34102001CryptoProAParamSet, oidGostR34102001CryptoProBParamSet,
		oidGostR34102001CryptoProCParamSet, oidGostR34102001CryptoProXchAParamSet,
		oidGostR34102001CryptoProXchBParamSet, oidTc26Gost341012256ParamSetA,
		oidTc26Gost341012256ParamSetB, oidTc26Gost341012256ParamSetC,
		oidTc26Gost341012256ParamSetD, oidTc26Gost341012512ParamSetT,
		oidTc26Gost341012512ParamSetA, oidTc26Gost341012512ParamSetB,
		oidTc26Gost341012512ParamSetC,
	}
	result := make(map[string]asn1.ObjectIdentifier, len(oids))
	for _, oid := range oids {
		der, err := asn1.Marshal(oid)
		if err != nil {
			panic(err)
		}
		tag, content, rest, ok := readDERElement(der)
		if !ok || tag != 0x06 || len(rest) != 0 {
			panic("gostx509: invalid built-in GOST OID")
		}
		result[string(content)] = oid
	}
	return result
}

func gostPublicKeyBytesView(bitStringBytes []byte, pointSize int) ([]byte, error) {
	want := 2 * pointSize
	if len(bitStringBytes) == want {
		return bitStringBytes, nil
	}
	if tag, octets, rest, ok := readDERElement(bitStringBytes); ok && tag == 0x04 && len(rest) == 0 && len(octets) == want {
		return octets, nil
	}
	if len(bitStringBytes) == want+1 && bitStringBytes[0] == 0x04 {
		return bitStringBytes[1:], nil
	}
	return nil, fmt.Errorf("%w: GOST public key length %d, want %d", ErrMalformedCertificate, len(bitStringBytes), want)
}

// VerifyGOST3410Digest проверяет распространённые кодировки подписи ГОСТ 34.10.
func VerifyGOST3410Digest(publicKey *gost3410.PublicKey, digest, signature []byte) (bool, error) {
	if publicKey == nil {
		return false, fmt.Errorf("%w: GOST public key is nil", ErrMalformedCertificate)
	}
	normalized, err := normalizeGOSTSignature(signature, publicKey.C.PointSize())
	if err != nil {
		return false, err
	}
	return verifyGOSTDigestFlexible(publicKey, digest, normalized)
}

func normalizeGOSTSignature(signature []byte, pointSize int) ([]byte, error) {
	want := 2 * pointSize
	if len(signature) == want {
		return signature, nil
	}
	var octets []byte
	if rest, err := asn1.Unmarshal(signature, &octets); err == nil && len(rest) == 0 && len(octets) == want {
		return octets, nil
	}
	return nil, fmt.Errorf("%w: GOST signature length %d, want %d", ErrMalformedCertificate, len(signature), want)
}

func verifyGOSTDigestFlexible(publicKey *gost3410.PublicKey, digest, signature []byte) (bool, error) {
	if len(digest) == 0 {
		return false, fmt.Errorf("%w: empty GOST digest", ErrMalformedCertificate)
	}
	verified, lastErr := publicKey.VerifyDigest(digest, signature)
	if lastErr == nil && verified {
		return true, nil
	}
	reversedSignature := reverseCopy(signature)
	if !bytes.Equal(signature, reversedSignature) {
		verified, err := publicKey.VerifyDigest(digest, reversedSignature)
		if err == nil && verified {
			return true, nil
		}
		if err != nil {
			lastErr = err
		}
	}
	reversedDigest := reverseCopy(digest)
	if subtle.ConstantTimeCompare(digest, reversedDigest) != 1 {
		verified, err := publicKey.VerifyDigest(reversedDigest, signature)
		if err == nil && verified {
			return true, nil
		}
		if err != nil {
			lastErr = err
		}
		if !bytes.Equal(signature, reversedSignature) {
			verified, err = publicKey.VerifyDigest(reversedDigest, reversedSignature)
			if err == nil && verified {
				return true, nil
			}
			if err != nil {
				lastErr = err
			}
		}
	}
	return false, lastErr
}

func digestForInfoSignatureAlgorithm(oid asn1.ObjectIdentifier, data []byte) ([]byte, string, error) {
	name, err := digestAlgorithmNameForSignatureAlgorithm(oid)
	if err != nil {
		return nil, "", err
	}
	switch name {
	case GOSTDigestAlgorithm2012256:
		digest := gost34112012256.Sum(data)
		return digest[:], name, nil
	case GOSTDigestAlgorithm2012512:
		digest := gost34112012512.Sum(data)
		return digest[:], name, nil
	default:
		return hashBytes(gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet), data), name, nil
	}
}

func digestAlgorithmNameForSignatureAlgorithm(oid asn1.ObjectIdentifier) (string, error) {
	switch {
	case oid.Equal(oidTc26Gost341012256Signature):
		return GOSTDigestAlgorithm2012256, nil
	case oid.Equal(oidTc26Gost341012512Signature):
		return GOSTDigestAlgorithm2012512, nil
	case oid.Equal(oidGostR34112001WithR34102001):
		return GOSTDigestAlgorithm341194, nil
	default:
		return "", fmt.Errorf("%w: unsupported signature algorithm OID %s", ErrUnsupportedCertificate, oid.String())
	}
}

func gostKeyAlgorithmName(oid asn1.ObjectIdentifier) (string, error) {
	switch {
	case oid.Equal(oidGostR34102001):
		return GOSTAlgorithm34102001, nil
	case oid.Equal(oidTc26Gost341012256):
		return GOSTAlgorithm34102012256, nil
	case oid.Equal(oidTc26Gost341012512):
		return GOSTAlgorithm34102012512, nil
	default:
		return "", fmt.Errorf("%w: unsupported GOST public key algorithm OID %s", ErrUnsupportedCertificate, oid.String())
	}
}

func gostSignatureAlgorithmName(oid asn1.ObjectIdentifier) string {
	switch {
	case oid.Equal(oidTc26Gost341012256Signature):
		return GOSTAlgorithm34102012256
	case oid.Equal(oidTc26Gost341012512Signature):
		return GOSTAlgorithm34102012512
	case oid.Equal(oidGostR34112001WithR34102001):
		return GOSTAlgorithm34102001
	default:
		return GOSTAlgorithmUnknown
	}
}

func gostDigestName(oid asn1.ObjectIdentifier) string {
	switch {
	case oid.Equal(oidTc26Gost34112012256):
		return GOSTDigestAlgorithm2012256
	case oid.Equal(oidTc26Gost34112012512):
		return GOSTDigestAlgorithm2012512
	case oid.Equal(oidGostR341194), oid.Equal(oidGostR341194CryptoProParamSet):
		return GOSTDigestAlgorithm341194
	default:
		return GOSTAlgorithmUnknown
	}
}

func gostOIDString(oid asn1.ObjectIdentifier) string {
	switch {
	case len(oid) == 0:
		return ""
	case oid.Equal(oidGostR34102001):
		return "1.2.643.2.2.19"
	case oid.Equal(oidGostR34112001WithR34102001):
		return "1.2.643.2.2.3"
	case oid.Equal(oidGostR341194):
		return "1.2.643.2.2.9"
	case oid.Equal(oidGostR341194CryptoProParamSet):
		return "1.2.643.2.2.30.1"
	case oid.Equal(oidGostR34102001CryptoProAParamSet):
		return "1.2.643.2.2.35.1"
	case oid.Equal(oidGostR34102001CryptoProBParamSet):
		return "1.2.643.2.2.35.2"
	case oid.Equal(oidGostR34102001CryptoProCParamSet):
		return "1.2.643.2.2.35.3"
	case oid.Equal(oidGostR34102001CryptoProXchAParamSet):
		return "1.2.643.2.2.36.0"
	case oid.Equal(oidGostR34102001CryptoProXchBParamSet):
		return "1.2.643.2.2.36.1"
	case oid.Equal(oidTc26Gost341012256):
		return "1.2.643.7.1.1.1.1"
	case oid.Equal(oidTc26Gost341012512):
		return "1.2.643.7.1.1.1.2"
	case oid.Equal(oidTc26Gost34112012256):
		return "1.2.643.7.1.1.2.2"
	case oid.Equal(oidTc26Gost34112012512):
		return "1.2.643.7.1.1.2.3"
	case oid.Equal(oidTc26Gost341012256Signature):
		return "1.2.643.7.1.1.3.2"
	case oid.Equal(oidTc26Gost341012512Signature):
		return "1.2.643.7.1.1.3.3"
	case oid.Equal(oidTc26Gost341012256ParamSetA):
		return "1.2.643.7.1.2.1.1.1"
	case oid.Equal(oidTc26Gost341012256ParamSetB):
		return "1.2.643.7.1.2.1.1.2"
	case oid.Equal(oidTc26Gost341012256ParamSetC):
		return "1.2.643.7.1.2.1.1.3"
	case oid.Equal(oidTc26Gost341012256ParamSetD):
		return "1.2.643.7.1.2.1.1.4"
	case oid.Equal(oidTc26Gost341012512ParamSetT):
		return "1.2.643.7.1.2.1.2.0"
	case oid.Equal(oidTc26Gost341012512ParamSetA):
		return "1.2.643.7.1.2.1.2.1"
	case oid.Equal(oidTc26Gost341012512ParamSetB):
		return "1.2.643.7.1.2.1.2.2"
	case oid.Equal(oidTc26Gost341012512ParamSetC):
		return "1.2.643.7.1.2.1.2.3"
	default:
		return oid.String()
	}
}

// ParsePublicKeyInfoPEM разбирает SubjectPublicKeyInfo ГОСТ из PEM либо DER.
func ParsePublicKeyInfoPEM(data []byte) (*GostPublicKeyInfo, error) {
	rest := data
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "PUBLIC KEY" {
			return ParsePublicKeyInfoDER(block.Bytes)
		}
		rest = next
	}
	return ParsePublicKeyInfoDER(data)
}

// ParsePublicKeyInfoDER разбирает DER SubjectPublicKeyInfo и нормализует параметры ГОСТ.
func ParsePublicKeyInfoDER(der []byte) (*GostPublicKeyInfo, error) {
	var spki subjectPublicKeyInfoMetadataASN1
	rest, err := asn1.Unmarshal(der, &spki)
	if err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("%w: malformed public key DER", ErrMalformedCertificate)
	}
	info, err := parseGostPublicKeyView(spki)
	if err != nil {
		return nil, err
	}
	info.PublicKeyRaw = cloneBytes(info.PublicKeyRaw)
	return info, nil
}

// MarshalPublicKeyInfoPEM кодирует открытый ключ ГОСТ в блок PUBLIC KEY PEM.
func MarshalPublicKeyInfoPEM(info *GostPublicKeyInfo) ([]byte, error) {
	der, err := MarshalPublicKeyInfoDER(info)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// MarshalPublicKeyInfoDER кодирует открытый ключ ГОСТ как SubjectPublicKeyInfo DER.
func MarshalPublicKeyInfoDER(info *GostPublicKeyInfo) ([]byte, error) {
	if info == nil || len(info.PublicKeyRaw) == 0 {
		return nil, fmt.Errorf("%w: public key is nil or empty", ErrMalformedCertificate)
	}
	algorithmOID, err := parseOIDString(info.AlgorithmOID)
	if err != nil {
		return nil, err
	}
	curveOID, err := parseOIDString(info.CurveOID)
	if err != nil {
		return nil, err
	}
	digestOID, err := publicKeyDigestOID(info)
	if err != nil {
		return nil, err
	}
	paramsDER, err := asn1.Marshal(gostPublicKeyInfoParameters{PublicKeyParamSet: curveOID, DigestParamSet: digestOID})
	if err != nil {
		return nil, fmt.Errorf("%w: marshal GOST public key parameters: %v", ErrMalformedCertificate, err)
	}
	keyDER, err := asn1.Marshal(info.PublicKeyRaw)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal GOST public key bytes: %v", ErrMalformedCertificate, err)
	}
	return asn1.Marshal(subjectPublicKeyInfoMetadataASN1{
		Algorithm:        algorithmIdentifierASN1{Algorithm: algorithmOID, Parameters: asn1.RawValue{FullBytes: paramsDER}},
		SubjectPublicKey: asn1.BitString{Bytes: keyDER, BitLength: len(keyDER) * 8},
	})
}

// VerifyDetachedSignatureWithPublicKeyInfo проверяет отделённую подпись по данным ключа ГОСТ.
func VerifyDetachedSignatureWithPublicKeyInfo(data, signature []byte, publicKey *GostPublicKeyInfo, signatureAlgorithmOID string) error {
	if publicKey == nil || publicKey.PublicKey == nil {
		return fmt.Errorf("%w: public key is nil or unsupported", ErrMalformedCertificate)
	}
	algorithmOID, err := publicKeySignatureOID(publicKey, signatureAlgorithmOID)
	if err != nil {
		return err
	}
	digest, _, err := digestForInfoSignatureAlgorithm(algorithmOID, data)
	if err != nil {
		return err
	}
	verified, err := VerifyGOST3410Digest(publicKey.PublicKey, digest, signature)
	if err != nil {
		return err
	}
	if !verified {
		return fmt.Errorf("%w: detached signature verification failed", ErrCertificateVerification)
	}
	return nil
}

func publicKeySignatureOID(publicKey *GostPublicKeyInfo, explicit string) (asn1.ObjectIdentifier, error) {
	if explicit != "" {
		oid, err := parseOIDString(explicit)
		if err != nil {
			return nil, err
		}
		if gostSignatureAlgorithmName(oid) != publicKey.Algorithm {
			return nil, fmt.Errorf("%w: signature algorithm OID %s does not match public key algorithm %s", ErrUnsupportedCertificate, explicit, publicKey.Algorithm)
		}
		return oid, nil
	}
	switch publicKey.Algorithm {
	case GOSTAlgorithm34102012256:
		return oidTc26Gost341012256Signature, nil
	case GOSTAlgorithm34102012512:
		return oidTc26Gost341012512Signature, nil
	case GOSTAlgorithm34102001:
		return oidGostR34112001WithR34102001, nil
	default:
		return nil, fmt.Errorf("%w: unsupported GOST public key algorithm %q", ErrUnsupportedCertificate, publicKey.Algorithm)
	}
}

func publicKeyDigestOID(info *GostPublicKeyInfo) (asn1.ObjectIdentifier, error) {
	if info.DigestOID != "" {
		return parseOIDString(info.DigestOID)
	}
	switch info.Algorithm {
	case GOSTAlgorithm34102012256:
		return oidTc26Gost34112012256, nil
	case GOSTAlgorithm34102012512:
		return oidTc26Gost34112012512, nil
	case GOSTAlgorithm34102001:
		return oidGostR341194CryptoProParamSet, nil
	default:
		return nil, fmt.Errorf("%w: unsupported GOST public key algorithm %q", ErrUnsupportedCertificate, info.Algorithm)
	}
}

func hashBytes(hash hash.Hash, data []byte) []byte {
	_, _ = hash.Write(data)
	return hash.Sum(nil)
}

func stringsUpperHex(data []byte) string {
	out := make([]byte, len(data)*2)
	const alphabet = "0123456789ABCDEF"
	for index, value := range data {
		out[index*2] = alphabet[value>>4]
		out[index*2+1] = alphabet[value&0x0f]
	}
	return string(out)
}

func cloneBytes(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	return append([]byte(nil), data...)
}

func reverseCopy(data []byte) []byte {
	result := make([]byte, len(data))
	for index := range data {
		result[index] = data[len(data)-1-index]
	}
	return result
}

// CertificateStatusInfo содержит состояние, вычисленное по сроку действия сертификата.
type CertificateStatusInfo struct {
	NotBeforeText string    `json:"not_before_text"`
	NotAfterText  string    `json:"not_after_text"`
	NotBeforeUnix int64     `json:"not_before_unix"`
	NotAfterUnix  int64     `json:"not_after_unix"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	Now           time.Time `json:"now"`
	DaysLeft      int       `json:"days_left"`
	ValidNow      bool      `json:"valid_now"`
	NotYetValid   bool      `json:"not_yet_valid,omitempty"`
	Expired       bool      `json:"expired,omitempty"`
	Status        uint8     `json:"status"`
}

const (
	CertificateStatusExpiredOrInvalid uint8 = iota
	CertificateStatusValid
	CertificateStatusExpiresToday
)

// CertificateInfoStatus вычисляет состояние срока действия сертификата.
func CertificateInfoStatus(cert *CertificateInfo, now time.Time) (CertificateStatusInfo, error) {
	if cert == nil {
		return CertificateStatusInfo{}, fmt.Errorf("%w: certificate is nil", ErrMalformedCertificate)
	}
	if now.IsZero() {
		now = time.Now()
	}
	now = now.In(cert.NotAfter.Location())
	status := CertificateStatusInfo{
		NotBeforeText: cert.NotBefore.Format("02.01.2006"), NotAfterText: cert.NotAfter.Format("02.01.2006"),
		NotBeforeUnix: cert.NotBefore.Unix(), NotAfterUnix: cert.NotAfter.Unix(),
		NotBefore: cert.NotBefore, NotAfter: cert.NotAfter, Now: now,
	}
	if now.Before(cert.NotBefore) {
		status.NotYetValid = true
		return status, nil
	}
	if now.After(cert.NotAfter) {
		status.Expired = true
		return status, nil
	}
	status.ValidNow = true
	status.DaysLeft = certificateDaysLeft(now, cert.NotAfter)
	switch {
	case status.DaysLeft > 3:
		status.Status = CertificateStatusValid
	case status.DaysLeft <= 0:
		status.Status = CertificateStatusExpiresToday
	default:
		status.Status = uint8(status.DaysLeft + 2)
	}
	return status, nil
}

func certificateDaysLeft(now, notAfter time.Time) int {
	nowDate := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	expires := notAfter.In(now.Location())
	expiresDate := time.Date(expires.Year(), expires.Month(), expires.Day(), 0, 0, 0, 0, now.Location())
	return int(expiresDate.Sub(nowDate).Hours() / 24)
}
