package gostx509

import (
	"bytes"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
	"unicode/utf8"

	"crypto/x509/pkix"
)

// CertificateInfo содержит нормализованные метаданные сертификата и поля,
// необходимые для быстрой проверки ГОСТ-подписей и явных цепочек доверия.
type CertificateInfo struct {
	RawDER                []byte              `json:"-"`
	TBSCertificateDER     []byte              `json:"-"`
	Signature             []byte              `json:"-"`
	SignatureAlgorithm    string              `json:"signature_algorithm,omitempty"`
	SignatureAlgorithmOID string              `json:"signature_algorithm_oid,omitempty"`
	DigestAlgorithm       string              `json:"digest_algorithm,omitempty"`
	SerialHex             string              `json:"serial_hex"`
	SerialDecimal         string              `json:"serial_decimal,omitempty"`
	Subject               string              `json:"subject"`
	Issuer                string              `json:"issuer"`
	CN                    string              `json:"cn,omitempty"`
	Email                 string              `json:"email,omitempty"`
	Organization          string              `json:"organization,omitempty"`
	NotBefore             time.Time           `json:"not_before"`
	NotAfter              time.Time           `json:"not_after"`
	PublicKeyAlgorithm    string              `json:"public_key_algorithm,omitempty"`
	PublicKeyAlgorithmOID string              `json:"public_key_algorithm_oid,omitempty"`
	Curve                 string              `json:"curve,omitempty"`
	CurveOID              string              `json:"curve_oid,omitempty"`
	PublicKeyRawHex       string              `json:"public_key_raw_hex,omitempty"`
	PublicKey             *GostPublicKeyInfo  `json:"-"`
	Extensions            []CertificateExtOID `json:"extensions,omitempty"`
	BasicConstraintsValid bool                `json:"basic_constraints_valid,omitempty"`
	IsCA                  bool                `json:"is_ca,omitempty"`
	MaxPathLen            int                 `json:"max_path_len,omitempty"`
	MaxPathLenZero        bool                `json:"max_path_len_zero,omitempty"`
	KeyUsage              CertificateKeyUsage `json:"key_usage,omitempty"`
	KeyUsagePresent       bool                `json:"key_usage_present,omitempty"`
	SubjectKeyID          []byte              `json:"subject_key_id,omitempty"`
	AuthorityKeyID        []byte              `json:"authority_key_id,omitempty"`
	UnhandledCriticalOIDs []string            `json:"unhandled_critical_oids,omitempty"`
	subjectRaw            []byte
	issuerRaw             []byte
}

// CertificateExtOID описывает OID расширения сертификата и признак critical.
type CertificateExtOID struct {
	OID      string `json:"oid"`
	Critical bool   `json:"critical,omitempty"`
}

// CertificateKeyUsage представляет битовую маску keyUsage из RFC 5280.
type CertificateKeyUsage uint16

const (
	CertificateKeyUsageDigitalSignature CertificateKeyUsage = 1 << iota
	CertificateKeyUsageContentCommitment
	CertificateKeyUsageKeyEncipherment
	CertificateKeyUsageDataEncipherment
	CertificateKeyUsageKeyAgreement
	CertificateKeyUsageCertSign
	CertificateKeyUsageCRLSign
	CertificateKeyUsageEncipherOnly
	CertificateKeyUsageDecipherOnly
)

// ChainVerifyOptions задаёт параметры построения и проверки цепочки сертификатов.
type ChainVerifyOptions struct {
	NoCheckTime bool
	CurrentTime time.Time
	// TrustedRoots содержит явный набор доверенных корневых сертификатов.
	// Сертификаты из intermediates не становятся точками доверия автоматически.
	TrustedRoots []*CertificateInfo
}

var (
	// ErrMalformedCertificate означает повреждённые данные сертификата, ключа или подписи.
	ErrMalformedCertificate = errors.New("gostx509: malformed certificate data")
	// ErrUnsupportedCertificate означает неподдерживаемый профиль X.509 или ГОСТ.
	ErrUnsupportedCertificate = errors.New("gostx509: unsupported certificate profile")
	// ErrCertificateVerification означает ошибку проверки подписи или цепочки.
	ErrCertificateVerification = errors.New("gostx509: certificate verification failed")
	// ErrCertificateNotFound означает, что сертификат издателя не найден.
	ErrCertificateNotFound = errors.New("gostx509: certificate issuer not found")
	// ErrNoTrustedRoots означает отсутствие явно заданных доверенных корней.
	ErrNoTrustedRoots = errors.New("gostx509: trusted root set is empty")
)

type algorithmIdentifierASN1 struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type certificateInfoASN1 struct {
	TBSCertificate     tbsCertificateInfoASN1
	SignatureAlgorithm algorithmIdentifierASN1
	SignatureValue     asn1.BitString
}

type tbsCertificateInfoASN1 struct {
	Raw                  asn1.RawContent
	Version              int `asn1:"optional,explicit,tag:0,default:0"`
	SerialNumber         *big.Int
	Signature            algorithmIdentifierASN1
	Issuer               asn1.RawValue
	Validity             validityInfoASN1
	Subject              asn1.RawValue
	SubjectPublicKeyInfo subjectPublicKeyInfoMetadataASN1
	IssuerUniqueID       asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueID      asn1.BitString   `asn1:"optional,tag:2"`
	Extensions           []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

type validityInfoASN1 struct {
	NotBefore time.Time
	NotAfter  time.Time
}

type subjectPublicKeyInfoMetadataASN1 struct {
	Raw              asn1.RawContent
	Algorithm        algorithmIdentifierASN1
	SubjectPublicKey asn1.BitString
}

var (
	oidEmailAddress            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	oidNameCommonName          = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidNameOrganization        = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidExtensionKeyUsage       = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtensionSubjectKeyID   = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidExtensionBasic          = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtensionAuthorityKeyID = asn1.ObjectIdentifier{2, 5, 29, 35}
)

// ParseCertificateInfo разбирает первый сертификат из PEM либо одиночный DER.
func ParseCertificateInfo(data []byte) (*CertificateInfo, error) {
	if len(data) > 0 && data[0] == 0x30 {
		return ParseCertificateInfoDER(data)
	}
	certs, err := ParseCertificateInfos(data)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("%w: no certificates found", ErrMalformedCertificate)
	}
	return certs[0], nil
}

// ParseCertificateInfoPEM разбирает первый блок CERTIFICATE из PEM.
func ParseCertificateInfoPEM(data []byte) (*CertificateInfo, error) {
	return ParseCertificateInfo(data)
}

// ParseCertificateInfoDER быстро разбирает необходимые метаданные DER-сертификата.
func ParseCertificateInfoDER(der []byte) (*CertificateInfo, error) {
	cert, ok := parseCertificateASN1Fast(der)
	if !ok {
		rest, err := asn1.Unmarshal(der, &cert)
		if err != nil || len(rest) != 0 {
			return nil, fmt.Errorf("%w: malformed certificate DER", ErrMalformedCertificate)
		}
	}
	if cert.TBSCertificate.SerialNumber == nil {
		return nil, fmt.Errorf("%w: malformed certificate DER", ErrMalformedCertificate)
	}
	tbs := &cert.TBSCertificate

	subjectName, err := parseCertificateName(tbs.Subject)
	if err != nil {
		return nil, err
	}
	issuerName, err := parseCertificateNameText(tbs.Issuer)
	if err != nil {
		return nil, err
	}

	publicKey, err := parseGostPublicKeyView(tbs.SubjectPublicKeyInfo)
	if err != nil {
		return nil, err
	}

	serialHex := stringsUpperHex(tbs.SerialNumber.Bytes())
	if serialHex == "" {
		serialHex = "00"
	}
	rawDER, tbsDER, signature, subjectRaw, issuerRaw, publicKeyRaw := cloneCertificateByteFields(
		der,
		tbs.Raw,
		cert.SignatureValue.Bytes,
		tbs.Subject.FullBytes,
		tbs.Issuer.FullBytes,
		publicKey.PublicKeyRaw,
	)
	publicKey.PublicKeyRaw = publicKeyRaw

	info := &CertificateInfo{
		RawDER:                rawDER,
		TBSCertificateDER:     tbsDER,
		Signature:             signature,
		SignatureAlgorithm:    gostSignatureAlgorithmName(cert.SignatureAlgorithm.Algorithm),
		SignatureAlgorithmOID: gostOIDString(cert.SignatureAlgorithm.Algorithm),
		SerialHex:             serialHex,
		SerialDecimal:         tbs.SerialNumber.String(),
		Subject:               subjectName.text,
		Issuer:                issuerName.text,
		CN:                    subjectName.commonName,
		Email:                 subjectName.email,
		Organization:          subjectName.organization,
		NotBefore:             tbs.Validity.NotBefore,
		NotAfter:              tbs.Validity.NotAfter,
		PublicKeyAlgorithm:    publicKey.Algorithm,
		PublicKeyAlgorithmOID: publicKey.AlgorithmOID,
		Curve:                 publicKey.Curve,
		CurveOID:              publicKey.CurveOID,
		PublicKeyRawHex:       publicKey.PublicKeyRawHex,
		PublicKey:             publicKey,
		Extensions:            make([]CertificateExtOID, 0, len(tbs.Extensions)),
		subjectRaw:            subjectRaw,
		issuerRaw:             issuerRaw,
	}
	if digestName, err := digestAlgorithmNameForSignatureAlgorithm(cert.SignatureAlgorithm.Algorithm); err == nil {
		info.DigestAlgorithm = digestName
	}
	for _, ext := range tbs.Extensions {
		info.Extensions = append(info.Extensions, CertificateExtOID{
			OID:      certificateExtensionOIDString(ext.Id),
			Critical: ext.Critical,
		})
	}
	if err := parseCertificateExtensions(info, tbs.Extensions); err != nil {
		return nil, err
	}
	return info, nil
}

func certificateExtensionOIDString(oid asn1.ObjectIdentifier) string {
	if len(oid) == 4 && oid[0] == 2 && oid[1] == 5 && oid[2] == 29 {
		switch oid[3] {
		case 14:
			return "2.5.29.14"
		case 15:
			return "2.5.29.15"
		case 16:
			return "2.5.29.16"
		case 17:
			return "2.5.29.17"
		case 19:
			return "2.5.29.19"
		case 30:
			return "2.5.29.30"
		case 31:
			return "2.5.29.31"
		case 32:
			return "2.5.29.32"
		case 33:
			return "2.5.29.33"
		case 35:
			return "2.5.29.35"
		case 36:
			return "2.5.29.36"
		case 37:
			return "2.5.29.37"
		case 46:
			return "2.5.29.46"
		case 54:
			return "2.5.29.54"
		}
	}
	if len(oid) == 9 && oid[0] == 1 && oid[1] == 3 && oid[2] == 6 && oid[3] == 1 &&
		oid[4] == 5 && oid[5] == 5 && oid[6] == 7 && oid[7] == 1 && oid[8] == 1 {
		return "1.3.6.1.5.5.7.1.1"
	}
	if len(oid) == 5 && oid[0] == 1 && oid[1] == 2 && oid[2] == 643 && oid[3] == 100 {
		switch oid[4] {
		case 111:
			return "1.2.643.100.111"
		case 112:
			return "1.2.643.100.112"
		case 114:
			return "1.2.643.100.114"
		}
	}
	if len(oid) == 7 && oid[0] == 1 && oid[1] == 2 && oid[2] == 643 &&
		oid[3] == 2 && oid[4] == 2 && oid[5] == 49 && oid[6] == 2 {
		return "1.2.643.2.2.49.2"
	}
	return oid.String()
}

func cloneCertificateByteFields(rawDERSource, tbsDERSource, signatureSource, subjectSource, issuerSource, publicKeySource []byte) (
	rawDER, tbsDER, signature, subject, issuer, publicKey []byte,
) {
	fields := [...][]byte{rawDERSource, tbsDERSource, signatureSource, subjectSource, issuerSource, publicKeySource}
	total := 0
	for _, field := range fields {
		total += len(field)
	}
	arena := make([]byte, total)
	offset := 0
	cloned := [...]*[]byte{&rawDER, &tbsDER, &signature, &subject, &issuer, &publicKey}
	for i, destination := range cloned {
		if len(fields[i]) == 0 {
			continue
		}
		end := offset + len(fields[i])
		copy(arena[offset:end], fields[i])
		*destination = arena[offset:end:end]
		offset = end
	}
	return rawDER, tbsDER, signature, subject, issuer, publicKey
}

func parseCertificateASN1Fast(der []byte) (certificateInfoASN1, bool) {
	var cert certificateInfoASN1
	tag, sequence, rest, ok := readDERElement(der)
	if !ok || tag != 0x30 || len(rest) != 0 {
		return cert, false
	}

	_, tbsFull, tbsContent, sequence, ok := readDERElementFull(sequence)
	if !ok || tbsFull[0] != 0x30 {
		return cert, false
	}
	tbs, ok := parseTBSCertificateFast(tbsFull, tbsContent)
	if !ok {
		return cert, false
	}
	cert.TBSCertificate = tbs

	_, algorithmFull, _, sequence, ok := readDERElementFull(sequence)
	if !ok {
		return certificateInfoASN1{}, false
	}
	cert.SignatureAlgorithm, ok = parseAlgorithmIdentifierFast(algorithmFull)
	if !ok {
		return certificateInfoASN1{}, false
	}

	tag, _, bitString, sequence, ok := readDERElementFull(sequence)
	if !ok || tag != 0x03 || len(sequence) != 0 {
		return certificateInfoASN1{}, false
	}
	cert.SignatureValue, ok = parseBitStringFast(bitString)
	return cert, ok
}

func parseTBSCertificateFast(full, sequence []byte) (tbsCertificateInfoASN1, bool) {
	var tbs tbsCertificateInfoASN1
	tbs.Raw = full

	if len(sequence) == 0 {
		return tbs, false
	}
	if sequence[0] == 0xa0 {
		tag, _, versionDER, rest, ok := readDERElementFull(sequence)
		if !ok || tag != 0xa0 {
			return tbs, false
		}
		versionTag, version, trailing, ok := readDERElement(versionDER)
		if !ok || versionTag != 0x02 || len(trailing) != 0 {
			return tbs, false
		}
		var valid bool
		tbs.Version, valid = parseSmallPositiveInteger(version)
		if !valid {
			return tbs, false
		}
		sequence = rest
	}

	tag, _, serial, rest, ok := readDERElementFull(sequence)
	if !ok || tag != 0x02 {
		return tbs, false
	}
	tbs.SerialNumber, ok = parsePositiveBigInteger(serial)
	if !ok {
		return tbs, false
	}
	sequence = rest

	_, algorithmFull, _, rest, ok := readDERElementFull(sequence)
	if !ok {
		return tbs, false
	}
	tbs.Signature, ok = parseAlgorithmIdentifierFast(algorithmFull)
	if !ok {
		return tbs, false
	}
	sequence = rest

	tag, issuerFull, _, rest, ok := readDERElementFull(sequence)
	if !ok || tag != 0x30 {
		return tbs, false
	}
	tbs.Issuer = asn1.RawValue{FullBytes: issuerFull}
	sequence = rest

	tag, validityFull, _, rest, ok := readDERElementFull(sequence)
	if !ok || tag != 0x30 {
		return tbs, false
	}
	tbs.Validity, ok = parseValidityFast(validityFull)
	if !ok {
		return tbs, false
	}
	sequence = rest

	tag, subjectFull, _, rest, ok := readDERElementFull(sequence)
	if !ok || tag != 0x30 {
		return tbs, false
	}
	tbs.Subject = asn1.RawValue{FullBytes: subjectFull}
	sequence = rest

	_, spkiFull, _, rest, ok := readDERElementFull(sequence)
	if !ok {
		return tbs, false
	}
	tbs.SubjectPublicKeyInfo, ok = parseSubjectPublicKeyInfoFast(spkiFull)
	if !ok {
		return tbs, false
	}
	sequence = rest

	lastOptional := byte(0)
	for len(sequence) > 0 {
		tag, _, content, rest, ok := readDERElementFull(sequence)
		if !ok {
			return tbs, false
		}
		switch tag {
		case 0x81:
			if lastOptional >= 1 {
				return tbs, false
			}
			tbs.IssuerUniqueID, ok = parseBitStringFast(content)
			lastOptional = 1
		case 0x82:
			if lastOptional >= 2 {
				return tbs, false
			}
			tbs.SubjectUniqueID, ok = parseBitStringFast(content)
			lastOptional = 2
		case 0xa3:
			if lastOptional >= 3 {
				return tbs, false
			}
			tbs.Extensions, ok = parseExtensionsFast(content)
			lastOptional = 3
		default:
			return tbs, false
		}
		if !ok {
			return tbs, false
		}
		sequence = rest
	}
	return tbs, true
}

func parseAlgorithmIdentifierFast(der []byte) (algorithmIdentifierASN1, bool) {
	var algorithm algorithmIdentifierASN1
	tag, sequence, rest, ok := readDERElement(der)
	if !ok || tag != 0x30 || len(rest) != 0 {
		return algorithm, false
	}
	tag, oidDER, sequence, ok := readDERElement(sequence)
	if !ok || tag != 0x06 {
		return algorithm, false
	}
	algorithm.Algorithm, ok = knownCertificateInfoGOSTOIDsByDER[string(oidDER)]
	if !ok {
		return algorithmIdentifierASN1{}, false
	}
	if len(sequence) == 0 {
		return algorithm, true
	}
	_, parameterFull, _, trailing, ok := readDERElementFull(sequence)
	if !ok || len(trailing) != 0 {
		return algorithmIdentifierASN1{}, false
	}
	algorithm.Parameters = asn1.RawValue{FullBytes: parameterFull}
	return algorithm, true
}

func parseSubjectPublicKeyInfoFast(der []byte) (subjectPublicKeyInfoMetadataASN1, bool) {
	var spki subjectPublicKeyInfoMetadataASN1
	tag, sequence, rest, ok := readDERElement(der)
	if !ok || tag != 0x30 || len(rest) != 0 {
		return spki, false
	}
	spki.Raw = der
	_, algorithmFull, _, sequence, ok := readDERElementFull(sequence)
	if !ok {
		return spki, false
	}
	spki.Algorithm, ok = parseAlgorithmIdentifierFast(algorithmFull)
	if !ok {
		return spki, false
	}
	tag, bitString, trailing, ok := readDERElement(sequence)
	if !ok || tag != 0x03 || len(trailing) != 0 {
		return spki, false
	}
	spki.SubjectPublicKey, ok = parseBitStringFast(bitString)
	return spki, ok
}

func parseBitStringFast(content []byte) (asn1.BitString, bool) {
	if len(content) == 0 || content[0] > 7 {
		return asn1.BitString{}, false
	}
	unused := int(content[0])
	bytes := content[1:]
	if len(bytes) == 0 {
		return asn1.BitString{}, unused == 0
	}
	if unused != 0 && bytes[len(bytes)-1]&byte((1<<unused)-1) != 0 {
		return asn1.BitString{}, false
	}
	return asn1.BitString{Bytes: bytes, BitLength: len(bytes)*8 - unused}, true
}

func parsePositiveBigInteger(content []byte) (*big.Int, bool) {
	if len(content) == 0 || content[0]&0x80 != 0 || len(content) > 1 && content[0] == 0 && content[1]&0x80 == 0 {
		return nil, false
	}
	return new(big.Int).SetBytes(content), true
}

func parseSmallPositiveInteger(content []byte) (int, bool) {
	if len(content) == 0 || content[0]&0x80 != 0 || len(content) > 1 && content[0] == 0 && content[1]&0x80 == 0 || len(content) > 4 {
		return 0, false
	}
	value := 0
	for _, octet := range content {
		value = value<<8 | int(octet)
	}
	return value, true
}

func parseValidityFast(der []byte) (validityInfoASN1, bool) {
	var validity validityInfoASN1
	tag, sequence, rest, ok := readDERElement(der)
	if !ok || tag != 0x30 || len(rest) != 0 {
		return validity, false
	}
	tag, notBefore, sequence, ok := readDERElement(sequence)
	if !ok {
		return validity, false
	}
	validity.NotBefore, ok = parseCertificateTimeFast(tag, notBefore)
	if !ok {
		return validityInfoASN1{}, false
	}
	tag, notAfter, trailing, ok := readDERElement(sequence)
	if !ok || len(trailing) != 0 {
		return validityInfoASN1{}, false
	}
	validity.NotAfter, ok = parseCertificateTimeFast(tag, notAfter)
	return validity, ok
}

func parseCertificateTimeFast(tag byte, value []byte) (time.Time, bool) {
	var year, offset int
	switch tag {
	case 0x17:
		if len(value) != 13 || value[12] != 'Z' {
			return time.Time{}, false
		}
		yearValue, ok := parseTwoDecimalDigits(value[0:2])
		if !ok {
			return time.Time{}, false
		}
		if yearValue >= 50 {
			year = 1900 + yearValue
		} else {
			year = 2000 + yearValue
		}
		offset = 2
	case 0x18:
		if len(value) != 15 || value[14] != 'Z' {
			return time.Time{}, false
		}
		first, ok := parseTwoDecimalDigits(value[0:2])
		if !ok {
			return time.Time{}, false
		}
		second, ok := parseTwoDecimalDigits(value[2:4])
		if !ok {
			return time.Time{}, false
		}
		year = first*100 + second
		offset = 4
	default:
		return time.Time{}, false
	}
	month, ok := parseTwoDecimalDigits(value[offset : offset+2])
	if !ok {
		return time.Time{}, false
	}
	day, ok := parseTwoDecimalDigits(value[offset+2 : offset+4])
	if !ok {
		return time.Time{}, false
	}
	hour, ok := parseTwoDecimalDigits(value[offset+4 : offset+6])
	if !ok {
		return time.Time{}, false
	}
	minute, ok := parseTwoDecimalDigits(value[offset+6 : offset+8])
	if !ok {
		return time.Time{}, false
	}
	second, ok := parseTwoDecimalDigits(value[offset+8 : offset+10])
	if !ok || second > 59 {
		return time.Time{}, false
	}
	parsed := time.Date(year, time.Month(month), day, hour, minute, second, 0, time.UTC)
	if parsed.Year() != year || int(parsed.Month()) != month || parsed.Day() != day ||
		parsed.Hour() != hour || parsed.Minute() != minute || parsed.Second() != second {
		return time.Time{}, false
	}
	return parsed, true
}

func parseTwoDecimalDigits(value []byte) (int, bool) {
	if len(value) != 2 || value[0] < '0' || value[0] > '9' || value[1] < '0' || value[1] > '9' {
		return 0, false
	}
	return int(value[0]-'0')*10 + int(value[1]-'0'), true
}

func parseExtensionsFast(explicit []byte) ([]pkix.Extension, bool) {
	tag, sequence, rest, ok := readDERElement(explicit)
	if !ok || tag != 0x30 || len(rest) != 0 {
		return nil, false
	}
	count, oidComponents := 0, 0
	for remaining := sequence; len(remaining) > 0; count++ {
		tag, extension, next, valid := readDERElement(remaining)
		if !valid || tag != 0x30 {
			return nil, false
		}
		remaining = next
		tag, oidDER, _, valid := readDERElement(extension)
		if !valid || tag != 0x06 {
			return nil, false
		}
		_, _, components, valid := inspectObjectIdentifierFast(oidDER)
		if !valid || oidComponents > int(^uint(0)>>1)-components {
			return nil, false
		}
		oidComponents += components
	}
	extensions := make([]pkix.Extension, count)
	oidStorage := make([]int, oidComponents)
	extensionIndex, oidOffset := 0, 0
	for len(sequence) > 0 {
		tag, extension, remaining, ok := readDERElement(sequence)
		if !ok || tag != 0x30 {
			return nil, false
		}
		sequence = remaining

		tag, oidDER, extension, ok := readDERElement(extension)
		if !ok || tag != 0x06 {
			return nil, false
		}
		oid, ok := parseObjectIdentifierFastInto(oidDER, oidStorage[oidOffset:])
		if !ok {
			return nil, false
		}
		oidOffset += len(oid)
		critical := false
		if len(extension) > 0 && extension[0] == 0x01 {
			tag, boolean, trailing, valid := readDERElement(extension)
			if !valid || tag != 0x01 || len(boolean) != 1 || boolean[0] != 0xff {
				return nil, false
			}
			critical = true
			extension = trailing
		}
		tag, value, trailing, ok := readDERElement(extension)
		if !ok || tag != 0x04 || len(trailing) != 0 {
			return nil, false
		}
		extensions[extensionIndex] = pkix.Extension{Id: oid, Critical: critical, Value: value}
		extensionIndex++
	}
	return extensions, true
}

func inspectObjectIdentifierFast(der []byte) (first uint64, rest []byte, components int, ok bool) {
	first, rest, ok = readCertificateNameOIDComponent(der)
	if !ok {
		return 0, nil, 0, false
	}
	components = 2
	for remaining := rest; len(remaining) > 0; components++ {
		_, remaining, ok = readCertificateNameOIDComponent(remaining)
		if !ok {
			return 0, nil, 0, false
		}
	}
	return first, rest, components, true
}

func parseObjectIdentifierFastInto(der []byte, storage []int) (asn1.ObjectIdentifier, bool) {
	first, rest, components, ok := inspectObjectIdentifierFast(der)
	if !ok || len(storage) < components {
		return nil, false
	}
	oid := asn1.ObjectIdentifier(storage[:components:components])
	switch {
	case first < 40:
		oid[0], oid[1] = 0, int(first)
	case first < 80:
		oid[0], oid[1] = 1, int(first-40)
	default:
		oid[0], oid[1] = 2, int(first-80)
	}
	index := 2
	for len(rest) > 0 {
		component, remaining, _ := readCertificateNameOIDComponent(rest)
		oid[index] = int(component)
		index++
		rest = remaining
	}
	return oid, true
}

// ParseCertificateInfos разбирает цепочку PEM либо одиночный DER-сертификат.
func ParseCertificateInfos(data []byte) ([]*CertificateInfo, error) {
	blocks := pemCertificateBlocks(data)
	if len(blocks) == 0 {
		cert, err := ParseCertificateInfoDER(data)
		if err != nil {
			return nil, err
		}
		return []*CertificateInfo{cert}, nil
	}

	certs := make([]*CertificateInfo, 0, len(blocks))
	for _, block := range blocks {
		cert, err := ParseCertificateInfoDER(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// VerifyDetachedSignatureInfo проверяет отделённую подпись открытым ключом сертификата.
func VerifyDetachedSignatureInfo(data, signature []byte, cert *CertificateInfo) error {
	if cert == nil {
		return fmt.Errorf("%w: certificate is nil", ErrMalformedCertificate)
	}
	return VerifyDetachedSignatureWithPublicKeyInfo(data, signature, cert.PublicKey, "")
}

// VerifyCertificateInfoChain строит и проверяет цепочку до одного из TrustedRoots.
func VerifyCertificateInfoChain(leaf *CertificateInfo, intermediates []*CertificateInfo, opts ChainVerifyOptions) error {
	if leaf == nil {
		return fmt.Errorf("%w: leaf certificate is nil", ErrMalformedCertificate)
	}
	if len(opts.TrustedRoots) == 0 {
		return fmt.Errorf("%w: trusted root set is empty", ErrNoTrustedRoots)
	}
	now := opts.CurrentTime
	if now.IsZero() {
		now = time.Now()
	}

	candidates := appendUniqueCertificates(nil, intermediates...)
	candidates = appendUniqueCertificates(candidates, opts.TrustedRoots...)
	visited := make(map[string]struct{}, len(candidates)+1)
	signatureChecks := 0
	return verifyCertificatePath(leaf, candidates, opts.TrustedRoots, now, opts.NoCheckTime, 0, 0, visited, &signatureChecks)
}

func verifyCertificatePath(
	current *CertificateInfo,
	candidates, roots []*CertificateInfo,
	now time.Time,
	noCheckTime bool,
	depth, caBelow int,
	visited map[string]struct{},
	signatureChecks *int,
) error {
	if current == nil {
		return fmt.Errorf("%w: nil certificate in path", ErrMalformedCertificate)
	}
	if depth > len(candidates)+1 {
		return fmt.Errorf("%w: certificate chain depth exceeded", ErrMalformedCertificate)
	}
	if err := validateCertificateForPath(current, now, noCheckTime, depth != 0, caBelow); err != nil {
		return err
	}
	key := string(current.RawDER)
	if _, ok := visited[key]; ok {
		return fmt.Errorf("%w: certificate chain loop at serial %s", ErrMalformedCertificate, current.SerialHex)
	}
	visited[key] = struct{}{}
	defer delete(visited, key)

	if certificateInSet(current, roots) {
		return nil
	}

	var pathErrors []error
	foundIssuer := false
	for _, issuer := range candidates {
		if issuer == nil || !sameCertificateName(current.issuerRaw, issuer.subjectRaw, current.Issuer, issuer.Subject) {
			continue
		}
		if !authorityKeyMatches(current, issuer) {
			continue
		}
		foundIssuer = true
		(*signatureChecks)++
		if *signatureChecks > maxChainSignatureChecks {
			return fmt.Errorf("%w: %w", ErrCertificateVerification, errSignatureLimit)
		}
		if err := VerifyCertificateInfoSignature(current, issuer); err != nil {
			pathErrors = append(pathErrors, err)
			continue
		}
		nextCABelow := caBelow
		if current.IsCA && !sameCertificateName(current.subjectRaw, current.issuerRaw, current.Subject, current.Issuer) {
			nextCABelow++
		}
		if err := verifyCertificatePath(issuer, candidates, roots, now, noCheckTime, depth+1, nextCABelow, visited, signatureChecks); err == nil {
			return nil
		} else {
			pathErrors = append(pathErrors, err)
		}
	}
	if !foundIssuer {
		return fmt.Errorf("%w: issuer not found for serial %s", ErrCertificateNotFound, current.SerialHex)
	}
	return fmt.Errorf("%w: no valid issuer path for serial %s: %v", ErrCertificateVerification, current.SerialHex, errors.Join(pathErrors...))
}

func validateCertificateForPath(cert *CertificateInfo, now time.Time, noCheckTime, requireCA bool, caBelow int) error {
	if err := checkCertificateInfoTime(cert, now, noCheckTime); err != nil {
		return err
	}
	if len(cert.UnhandledCriticalOIDs) != 0 {
		return fmt.Errorf("%w: certificate serial %s has unsupported critical extensions %s", ErrUnsupportedCertificate, cert.SerialHex, strings.Join(cert.UnhandledCriticalOIDs, ","))
	}
	if !requireCA {
		return nil
	}
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return fmt.Errorf("%w: issuer serial %s is not a CA", ErrCertificateVerification, cert.SerialHex)
	}
	if cert.KeyUsagePresent && cert.KeyUsage&CertificateKeyUsageCertSign == 0 {
		return fmt.Errorf("%w: issuer serial %s lacks keyCertSign usage", ErrCertificateVerification, cert.SerialHex)
	}
	if (cert.MaxPathLen >= 0 || cert.MaxPathLenZero) && caBelow > cert.MaxPathLen {
		return fmt.Errorf("%w: issuer serial %s path length %d exceeds %d", ErrCertificateVerification, cert.SerialHex, caBelow, cert.MaxPathLen)
	}
	return nil
}

func appendUniqueCertificates(dst []*CertificateInfo, certificates ...*CertificateInfo) []*CertificateInfo {
	for _, cert := range certificates {
		if cert != nil && !certificateInSet(cert, dst) {
			dst = append(dst, cert)
		}
	}
	return dst
}

func certificateInSet(cert *CertificateInfo, set []*CertificateInfo) bool {
	if cert == nil {
		return false
	}
	for _, candidate := range set {
		if candidate != nil && bytes.Equal(cert.RawDER, candidate.RawDER) {
			return true
		}
	}
	return false
}

func authorityKeyMatches(cert, issuer *CertificateInfo) bool {
	if len(cert.AuthorityKeyID) == 0 || len(issuer.SubjectKeyID) == 0 {
		return true
	}
	return bytes.Equal(cert.AuthorityKeyID, issuer.SubjectKeyID)
}

// VerifyCertificateInfoSignature проверяет подпись cert открытым ключом issuer.
func VerifyCertificateInfoSignature(cert, issuer *CertificateInfo) error {
	if cert == nil || issuer == nil {
		return fmt.Errorf("%w: certificate or issuer is nil", ErrMalformedCertificate)
	}
	if issuer.PublicKey == nil || issuer.PublicKey.PublicKey == nil {
		return fmt.Errorf("%w: issuer has no supported GOST public key", ErrUnsupportedCertificate)
	}
	algOID, err := parseOIDString(cert.SignatureAlgorithmOID)
	if err != nil {
		return err
	}
	digest, _, err := digestForInfoSignatureAlgorithm(algOID, cert.TBSCertificateDER)
	if err != nil {
		return err
	}
	ok, err := VerifyGOST3410Digest(issuer.PublicKey.PublicKey, digest, cert.Signature)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: certificate signature verification failed for serial %s", ErrCertificateVerification, cert.SerialHex)
	}
	return nil
}

func pemCertificateBlocks(data []byte) []*pem.Block {
	var blocks []*pem.Block
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			blocks = append(blocks, block)
		}
	}
	return blocks
}

type parsedCertificateName struct {
	text         string
	commonName   string
	organization string
	email        string
}

type fastCertificateNameAttribute struct {
	kind  byte
	oid   []byte
	value []byte
}

func parseCertificateName(raw asn1.RawValue) (parsedCertificateName, error) {
	return parseCertificateNameFields(raw, true)
}

func parseCertificateNameText(raw asn1.RawValue) (parsedCertificateName, error) {
	return parseCertificateNameFields(raw, false)
}

func parseCertificateNameFields(raw asn1.RawValue, includeFields bool) (parsedCertificateName, error) {
	if name, ok := parseCertificateNameFastFields(raw.FullBytes, includeFields); ok {
		return name, nil
	}
	var rdn pkix.RDNSequence
	rest, err := asn1.Unmarshal(raw.FullBytes, &rdn)
	if err != nil || len(rest) != 0 {
		return parsedCertificateName{}, fmt.Errorf("%w: malformed certificate name", ErrMalformedCertificate)
	}
	var name parsedCertificateName
	if includeFields {
		organizationSet := false
		for _, set := range rdn {
			for _, attr := range set {
				value, isString := attr.Value.(string)
				switch certificateNameAttributeKind(attr.Type) {
				case 3:
					if isString {
						name.commonName = value
					}
				case 10:
					if isString && !organizationSet {
						name.organization = value
						organizationSet = true
					}
				}
				if attr.Type.Equal(oidEmailAddress) {
					if isString {
						name.email = value
					} else {
						name.email = fmt.Sprint(attr.Value)
					}
				}
			}
		}
	}
	name.text = formatCertificateName(rdn, len(raw.FullBytes))
	return name, nil
}

func parseCertificateNameFastFields(der []byte, includeFields bool) (parsedCertificateName, bool) {
	tag, sequence, rest, ok := readDERElement(der)
	if !ok || tag != 0x30 || len(rest) != 0 {
		return parsedCertificateName{}, false
	}

	var storage [32]fastCertificateNameAttribute
	attributes := storage[:0]
	var name parsedCertificateName
	organizationSet := false
	for len(sequence) > 0 {
		tag, set, next, ok := readDERElement(sequence)
		if !ok || tag != 0x31 {
			return parsedCertificateName{}, false
		}
		sequence = next
		for len(set) > 0 {
			if len(attributes) == cap(attributes) {
				return parsedCertificateName{}, false
			}
			tag, attribute, next, ok := readDERElement(set)
			if !ok || tag != 0x30 {
				return parsedCertificateName{}, false
			}
			set = next
			oidTag, oid, attribute, ok := readDERElement(attribute)
			if !ok || oidTag != 0x06 || len(oid) == 0 {
				return parsedCertificateName{}, false
			}
			valueTag, valueDER, trailing, ok := readDERElement(attribute)
			if !ok || len(trailing) != 0 || !validCertificateNameOID(oid) {
				return parsedCertificateName{}, false
			}
			value, ok := decodeCertificateNameString(valueTag, valueDER)
			if !ok {
				return parsedCertificateName{}, false
			}

			kind := certificateNameAttributeKindDER(oid)
			attributes = append(attributes, fastCertificateNameAttribute{kind: kind, oid: oid, value: value})
			if includeFields {
				switch kind {
				case 3:
					name.commonName = string(value)
				case 10:
					if !organizationSet {
						name.organization = string(value)
						organizationSet = true
					}
				}
				if isCertificateEmailOID(oid) {
					name.email = string(value)
				}
			}
		}
	}
	name.text = formatFastCertificateName(attributes, len(der))
	return name, true
}

func readDERElement(data []byte) (tag byte, content, rest []byte, ok bool) {
	if len(data) < 2 || data[0]&0x1f == 0x1f {
		return 0, nil, nil, false
	}
	tag = data[0]
	length := int(data[1])
	headerLen := 2
	if length&0x80 != 0 {
		lengthBytes := length & 0x7f
		if lengthBytes == 0 || lengthBytes > 4 || len(data) < 2+lengthBytes || data[2] == 0 {
			return 0, nil, nil, false
		}
		length = 0
		for _, value := range data[2 : 2+lengthBytes] {
			if length > (int(^uint(0)>>1)-int(value))/256 {
				return 0, nil, nil, false
			}
			length = length*256 + int(value)
		}
		if length < 128 {
			return 0, nil, nil, false
		}
		headerLen += lengthBytes
	}
	if length > len(data)-headerLen {
		return 0, nil, nil, false
	}
	return tag, data[headerLen : headerLen+length], data[headerLen+length:], true
}

func readDERElementFull(data []byte) (tag byte, full, content, rest []byte, ok bool) {
	tag, content, rest, ok = readDERElement(data)
	if !ok {
		return 0, nil, nil, nil, false
	}
	return tag, data[:len(data)-len(rest)], content, rest, true
}

func decodeCertificateNameString(tag byte, data []byte) ([]byte, bool) {
	switch tag {
	case 0x0c:
		if !utf8.Valid(data) {
			return nil, false
		}
	case 0x12:
		for _, value := range data {
			if value != ' ' && (value < '0' || value > '9') {
				return nil, false
			}
		}
	case 0x13:
		for _, value := range data {
			if !isCertificateNamePrintable(value, true) {
				return nil, false
			}
		}
	case 0x16:
		for _, value := range data {
			if value >= utf8.RuneSelf {
				return nil, false
			}
		}
	default:
		return nil, false
	}
	return data, true
}

func formatFastCertificateName(attributes []fastCertificateNameAttribute, sizeHint int) string {
	var out strings.Builder
	if sizeHint <= int(^uint(0)>>1)/2 {
		out.Grow(sizeHint * 2)
	}
	first := true
	appendLastFastCertificateNameAttribute(&out, &first, attributes, 5, "SERIALNUMBER")
	appendLastFastCertificateNameAttribute(&out, &first, attributes, 3, "CN")
	appendFastCertificateNameAttributeGroup(&out, &first, attributes, 11, "OU")
	appendFastCertificateNameAttributeGroup(&out, &first, attributes, 10, "O")
	appendFastCertificateNameAttributeGroup(&out, &first, attributes, 17, "POSTALCODE")
	appendFastCertificateNameAttributeGroup(&out, &first, attributes, 9, "STREET")
	appendFastCertificateNameAttributeGroup(&out, &first, attributes, 7, "L")
	appendFastCertificateNameAttributeGroup(&out, &first, attributes, 8, "ST")
	appendFastCertificateNameAttributeGroup(&out, &first, attributes, 6, "C")
	for i := len(attributes); i > 0; {
		i--
		attribute := attributes[i]
		if attribute.kind != 0 {
			continue
		}
		appendCertificateNameSeparator(&out, &first, ',')
		appendCertificateNameOID(&out, attribute.oid)
		out.WriteString("=#")
		appendCertificateNameStringDERHexBytes(&out, attribute.value)
	}
	return out.String()
}

func appendLastFastCertificateNameAttribute(out *strings.Builder, first *bool, attributes []fastCertificateNameAttribute, kind byte, label string) {
	for i := len(attributes); i > 0; {
		i--
		if attributes[i].kind == kind {
			appendCertificateNameSeparator(out, first, ',')
			out.WriteString(label)
			out.WriteByte('=')
			appendEscapedCertificateNameValueBytes(out, attributes[i].value)
			return
		}
	}
}

func appendFastCertificateNameAttributeGroup(out *strings.Builder, first *bool, attributes []fastCertificateNameAttribute, kind byte, label string) {
	groupStarted := false
	for i := range attributes {
		if attributes[i].kind != kind {
			continue
		}
		if !groupStarted {
			appendCertificateNameSeparator(out, first, ',')
			groupStarted = true
		} else {
			out.WriteByte('+')
		}
		out.WriteString(label)
		out.WriteByte('=')
		appendEscapedCertificateNameValueBytes(out, attributes[i].value)
	}
}

func certificateNameAttributeKindDER(oid []byte) byte {
	if len(oid) != 3 || oid[0] != 0x55 || oid[1] != 0x04 {
		return 0
	}
	switch oid[2] {
	case 3, 5, 6, 7, 8, 9, 10, 11, 17:
		return oid[2]
	default:
		return 0
	}
}

func isCertificateEmailOID(oid []byte) bool {
	return len(oid) == 9 && oid[0] == 0x2a && oid[1] == 0x86 && oid[2] == 0x48 &&
		oid[3] == 0x86 && oid[4] == 0xf7 && oid[5] == 0x0d && oid[6] == 0x01 &&
		oid[7] == 0x09 && oid[8] == 0x01
}

func validCertificateNameOID(oid []byte) bool {
	_, rest, ok := readCertificateNameOIDComponent(oid)
	if !ok {
		return false
	}
	for len(rest) > 0 {
		_, rest, ok = readCertificateNameOIDComponent(rest)
		if !ok {
			return false
		}
	}
	return true
}

func readCertificateNameOIDComponent(data []byte) (uint64, []byte, bool) {
	if len(data) == 0 || data[0] == 0x80 {
		return 0, nil, false
	}
	var value uint64
	for i, octet := range data {
		if value > (^uint64(0) >> 7) {
			return 0, nil, false
		}
		value = value<<7 | uint64(octet&0x7f)
		if octet&0x80 == 0 {
			if value > uint64(^uint(0)>>1) {
				return 0, nil, false
			}
			return value, data[i+1:], true
		}
	}
	return 0, nil, false
}

func appendCertificateNameOID(out *strings.Builder, oid []byte) {
	first, rest, _ := readCertificateNameOIDComponent(oid)
	switch {
	case first < 40:
		out.WriteString("0.")
		appendCertificateNameDecimal(out, first)
	case first < 80:
		out.WriteString("1.")
		appendCertificateNameDecimal(out, first-40)
	default:
		out.WriteString("2.")
		appendCertificateNameDecimal(out, first-80)
	}
	for len(rest) > 0 {
		component, next, _ := readCertificateNameOIDComponent(rest)
		out.WriteByte('.')
		appendCertificateNameDecimal(out, component)
		rest = next
	}
}

func appendCertificateNameDecimal(out *strings.Builder, value uint64) {
	var buffer [20]byte
	position := len(buffer)
	for {
		position--
		buffer[position] = byte(value%10) + '0'
		value /= 10
		if value == 0 {
			out.Write(buffer[position:])
			return
		}
	}
}

func appendCertificateNameStringDERHexBytes(out *strings.Builder, value []byte) {
	tag := byte(0x13)
	for i := 0; i < len(value); i++ {
		if !isCertificateNamePrintable(value[i], false) {
			tag = 0x0c
			break
		}
	}
	appendLowerHexByte(out, tag)
	appendCertificateNameDERLengthHex(out, len(value))
	const alphabet = "0123456789abcdef"
	for i := 0; i < len(value); i++ {
		out.WriteByte(alphabet[value[i]>>4])
		out.WriteByte(alphabet[value[i]&0x0f])
	}
}

func appendCertificateNameDERLengthHex(out *strings.Builder, length int) {
	if length < 128 {
		appendLowerHexByte(out, byte(length))
		return
	}
	var buffer [8]byte
	position := len(buffer)
	for value := uint(length); value > 0; value >>= 8 {
		position--
		buffer[position] = byte(value)
	}
	appendLowerHexByte(out, 0x80|byte(len(buffer)-position))
	for _, value := range buffer[position:] {
		appendLowerHexByte(out, value)
	}
}

func appendLowerHexByte(out *strings.Builder, value byte) {
	const alphabet = "0123456789abcdef"
	out.WriteByte(alphabet[value>>4])
	out.WriteByte(alphabet[value&0x0f])
}

func isCertificateNamePrintable(value byte, relaxed bool) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' || value >= '\'' && value <= ')' ||
		value >= '+' && value <= '/' || value == ' ' || value == ':' ||
		value == '=' || value == '?' || relaxed && (value == '*' || value == '&')
}

func formatCertificateName(rdn pkix.RDNSequence, sizeHint int) string {
	var out strings.Builder
	// Unknown attributes are rendered as DER hex, so the textual form can be
	// almost twice as large as the encoded RDN sequence.
	if sizeHint <= int(^uint(0)>>1)/2 {
		out.Grow(sizeHint * 2)
	}
	first := true
	appendLastCertificateNameAttribute(&out, &first, rdn, 5, "SERIALNUMBER")
	appendLastCertificateNameAttribute(&out, &first, rdn, 3, "CN")
	appendCertificateNameAttributeGroup(&out, &first, rdn, 11, "OU")
	appendCertificateNameAttributeGroup(&out, &first, rdn, 10, "O")
	appendCertificateNameAttributeGroup(&out, &first, rdn, 17, "POSTALCODE")
	appendCertificateNameAttributeGroup(&out, &first, rdn, 9, "STREET")
	appendCertificateNameAttributeGroup(&out, &first, rdn, 7, "L")
	appendCertificateNameAttributeGroup(&out, &first, rdn, 8, "ST")
	appendCertificateNameAttributeGroup(&out, &first, rdn, 6, "C")

	for setIndex := len(rdn) - 1; setIndex >= 0; setIndex-- {
		set := rdn[setIndex]
		for attrIndex := len(set) - 1; attrIndex >= 0; attrIndex-- {
			attr := set[attrIndex]
			if certificateNameAttributeKind(attr.Type) != 0 {
				continue
			}
			appendCertificateNameSeparator(&out, &first, ',')
			appendUnknownCertificateNameAttribute(&out, attr)
		}
	}
	return out.String()
}

func appendLastCertificateNameAttribute(out *strings.Builder, first *bool, rdn pkix.RDNSequence, kind byte, label string) {
	value := ""
	found := false
	for _, set := range rdn {
		for _, attr := range set {
			if certificateNameAttributeKind(attr.Type) != kind {
				continue
			}
			if text, ok := attr.Value.(string); ok {
				value = text
				found = true
			}
		}
	}
	if found {
		appendCertificateNameSeparator(out, first, ',')
		out.WriteString(label)
		out.WriteByte('=')
		appendEscapedCertificateNameValue(out, value)
	}
}

func appendCertificateNameAttributeGroup(out *strings.Builder, first *bool, rdn pkix.RDNSequence, kind byte, label string) {
	groupStarted := false
	for _, set := range rdn {
		for _, attr := range set {
			if certificateNameAttributeKind(attr.Type) != kind {
				continue
			}
			value, ok := attr.Value.(string)
			if !ok {
				continue
			}
			if !groupStarted {
				appendCertificateNameSeparator(out, first, ',')
				groupStarted = true
			} else {
				out.WriteByte('+')
			}
			out.WriteString(label)
			out.WriteByte('=')
			appendEscapedCertificateNameValue(out, value)
		}
	}
}

func appendUnknownCertificateNameAttribute(out *strings.Builder, attr pkix.AttributeTypeAndValue) {
	if attr.Type.Equal(oidEmailAddress) {
		out.WriteString("1.2.840.113549.1.9.1")
	} else {
		out.WriteString(attr.Type.String())
	}
	if der, err := asn1.Marshal(attr.Value); err == nil {
		out.WriteString("=#")
		appendLowerHex(out, der)
		return
	}
	out.WriteByte('=')
	appendEscapedCertificateNameValue(out, fmt.Sprint(attr.Value))
}

func appendCertificateNameSeparator(out *strings.Builder, first *bool, separator byte) {
	if *first {
		*first = false
		return
	}
	out.WriteByte(separator)
}

func appendEscapedCertificateNameValue(out *strings.Builder, value string) {
	for index, char := range value {
		escape := false
		switch char {
		case ',', '+', '"', '\\', '<', '>', ';':
			escape = true
		case ' ':
			escape = index == 0 || index == len(value)-1
		case '#':
			escape = index == 0
		}
		if escape {
			out.WriteByte('\\')
		}
		out.WriteRune(char)
	}
}

func appendEscapedCertificateNameValueBytes(out *strings.Builder, value []byte) {
	for index := 0; index < len(value); {
		char, size := utf8.DecodeRune(value[index:])
		escape := false
		switch char {
		case ',', '+', '"', '\\', '<', '>', ';':
			escape = true
		case ' ':
			escape = index == 0 || index+size == len(value)
		case '#':
			escape = index == 0
		}
		if escape {
			out.WriteByte('\\')
		}
		out.WriteRune(char)
		index += size
	}
}

func appendLowerHex(out *strings.Builder, data []byte) {
	const alphabet = "0123456789abcdef"
	for _, value := range data {
		out.WriteByte(alphabet[value>>4])
		out.WriteByte(alphabet[value&0x0f])
	}
}

func certificateNameAttributeKind(oid asn1.ObjectIdentifier) byte {
	if len(oid) != 4 || oid[0] != 2 || oid[1] != 5 || oid[2] != 4 {
		return 0
	}
	switch oid[3] {
	case 3, 5, 6, 7, 8, 9, 10, 11, 17:
		return byte(oid[3])
	default:
		return 0
	}
}

func checkCertificateInfoTime(cert *CertificateInfo, now time.Time, noCheck bool) error {
	if noCheck {
		return nil
	}
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("%w: certificate serial %s is not valid before %s", ErrCertificateVerification, cert.SerialHex, cert.NotBefore.Format(time.RFC3339))
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("%w: certificate serial %s expired at %s", ErrCertificateVerification, cert.SerialHex, cert.NotAfter.Format(time.RFC3339))
	}
	return nil
}

func sameCertificateName(aRaw, bRaw []byte, aText, bText string) bool {
	if len(aRaw) != 0 && len(bRaw) != 0 {
		return bytes.Equal(aRaw, bRaw)
	}
	return aText == bText
}

func parseCertificateExtensions(info *CertificateInfo, extensions []pkix.Extension) error {
	info.MaxPathLen = -1
	for _, ext := range extensions {
		switch {
		case ext.Id.Equal(oidExtensionBasic):
			if isCA, maxPathLen, ok := parseBasicConstraintsExtensionFast(ext.Value); ok {
				info.BasicConstraintsValid = true
				info.IsCA = isCA
				info.MaxPathLen = maxPathLen
				info.MaxPathLenZero = maxPathLen == 0
				continue
			}
			var value struct {
				IsCA       bool `asn1:"optional"`
				MaxPathLen int  `asn1:"optional,default:-1"`
			}
			rest, err := asn1.Unmarshal(ext.Value, &value)
			if err != nil || len(rest) != 0 {
				return fmt.Errorf("%w: malformed basicConstraints extension", ErrMalformedCertificate)
			}
			info.BasicConstraintsValid = true
			info.IsCA = value.IsCA
			info.MaxPathLen = value.MaxPathLen
			info.MaxPathLenZero = value.MaxPathLen == 0
		case ext.Id.Equal(oidExtensionKeyUsage):
			if usage, ok := parseKeyUsageExtensionFast(ext.Value); ok {
				info.KeyUsagePresent = true
				info.KeyUsage = usage
				continue
			}
			var bits asn1.BitString
			rest, err := asn1.Unmarshal(ext.Value, &bits)
			if err != nil || len(rest) != 0 {
				return fmt.Errorf("%w: malformed keyUsage extension", ErrMalformedCertificate)
			}
			info.KeyUsagePresent = true
			for bit := 0; bit <= 8; bit++ {
				if bits.At(bit) != 0 {
					info.KeyUsage |= 1 << bit
				}
			}
		case ext.Id.Equal(oidExtensionSubjectKeyID):
			if id, ok := parseSubjectKeyIDExtensionFast(ext.Value); ok {
				info.SubjectKeyID = cloneBytes(id)
				continue
			}
			var id []byte
			rest, err := asn1.Unmarshal(ext.Value, &id)
			if err != nil || len(rest) != 0 || len(id) == 0 {
				return fmt.Errorf("%w: malformed subjectKeyIdentifier extension", ErrMalformedCertificate)
			}
			info.SubjectKeyID = cloneBytes(id)
		case ext.Id.Equal(oidExtensionAuthorityKeyID):
			if id, ok := parseAuthorityKeyIDExtensionFast(ext.Value); ok {
				info.AuthorityKeyID = cloneBytes(id)
				continue
			}
			var value struct {
				ID []byte `asn1:"optional,tag:0"`
			}
			rest, err := asn1.Unmarshal(ext.Value, &value)
			if err != nil || len(rest) != 0 {
				return fmt.Errorf("%w: malformed authorityKeyIdentifier extension", ErrMalformedCertificate)
			}
			info.AuthorityKeyID = cloneBytes(value.ID)
		default:
			if ext.Critical {
				info.UnhandledCriticalOIDs = append(info.UnhandledCriticalOIDs, ext.Id.String())
			}
		}
	}
	return nil
}

func parseBasicConstraintsExtensionFast(der []byte) (isCA bool, maxPathLen int, ok bool) {
	tag, sequence, rest, ok := readDERElement(der)
	if !ok || tag != 0x30 || len(rest) != 0 {
		return false, 0, false
	}
	maxPathLen = -1
	if len(sequence) > 0 && sequence[0] == 0x01 {
		tag, value, next, valid := readDERElement(sequence)
		if !valid || tag != 0x01 || len(value) != 1 {
			return false, 0, false
		}
		isCA = value[0] != 0
		sequence = next
	}
	if len(sequence) == 0 {
		return isCA, maxPathLen, true
	}
	tag, value, trailing, valid := readDERElement(sequence)
	if !valid || tag != 0x02 || len(trailing) != 0 {
		return false, 0, false
	}
	maxPathLen, valid = parseNonnegativeDERInt(value)
	if !valid {
		return false, 0, false
	}
	return isCA, maxPathLen, true
}

func parseNonnegativeDERInt(der []byte) (int, bool) {
	if len(der) == 0 || der[0]&0x80 != 0 || len(der) > 1 && der[0] == 0 && der[1]&0x80 == 0 {
		return 0, false
	}
	const maxInt = int(^uint(0) >> 1)
	value := 0
	for _, octet := range der {
		if value > (maxInt-int(octet))/256 {
			return 0, false
		}
		value = value*256 + int(octet)
	}
	return value, true
}

func parseKeyUsageExtensionFast(der []byte) (CertificateKeyUsage, bool) {
	tag, bitString, rest, ok := readDERElement(der)
	if !ok || tag != 0x03 || len(rest) != 0 || len(bitString) == 0 || bitString[0] > 7 {
		return 0, false
	}
	unused := int(bitString[0])
	bits := bitString[1:]
	if len(bits) == 0 {
		return 0, unused == 0
	}
	if unused != 0 && bits[len(bits)-1]&byte(1<<uint(unused)-1) != 0 {
		return 0, false
	}
	bitLength := len(bits)*8 - unused
	var usage CertificateKeyUsage
	for bit := 0; bit <= 8 && bit < bitLength; bit++ {
		if bits[bit/8]&(1<<uint(7-bit%8)) != 0 {
			usage |= 1 << bit
		}
	}
	return usage, true
}

func parseSubjectKeyIDExtensionFast(der []byte) ([]byte, bool) {
	tag, id, rest, ok := readDERElement(der)
	return id, ok && tag == 0x04 && len(rest) == 0 && len(id) != 0
}

func parseAuthorityKeyIDExtensionFast(der []byte) ([]byte, bool) {
	tag, sequence, rest, ok := readDERElement(der)
	if !ok || tag != 0x30 || len(rest) != 0 {
		return nil, false
	}
	if len(sequence) == 0 {
		return nil, true
	}
	tag, id, trailing, ok := readDERElement(sequence)
	return id, ok && tag == 0x80 && len(trailing) == 0
}

func parseOIDString(s string) (asn1.ObjectIdentifier, error) {
	if s == "" {
		return nil, fmt.Errorf("%w: empty OID", ErrMalformedCertificate)
	}
	components := 1
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			components++
		}
	}
	oid := make(asn1.ObjectIdentifier, components)
	component, value, digits := 0, 0, 0
	const maxInt = int(^uint(0) >> 1)
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			if digits == 0 {
				return nil, fmt.Errorf("%w: malformed OID %q", ErrMalformedCertificate, s)
			}
			oid[component] = value
			component++
			value, digits = 0, 0
			continue
		}
		if s[i] < '0' || s[i] > '9' {
			return nil, fmt.Errorf("%w: malformed OID %q", ErrMalformedCertificate, s)
		}
		digit := int(s[i] - '0')
		if value > (maxInt-digit)/10 {
			return nil, fmt.Errorf("%w: malformed OID %q", ErrMalformedCertificate, s)
		}
		value = value*10 + digit
		digits++
	}
	return oid, nil
}
