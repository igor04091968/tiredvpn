package cms

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"time"

	"gitverse.ru/uzer_007/gogost/v3/gost34112012256"
	"gitverse.ru/uzer_007/gogost/v3/gost34112012512"
	"gitverse.ru/uzer_007/gogost/v3/gostx509"
)

var ErrTimeStamp = errors.New("gogost/cms: Некорректная метка времени RFC 3161")

var (
	oidExtendedKeyUsage  = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidTimeStampingUsage = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
)

// TimeStampToken is an RFC 3161 TSTInfo carried by CMS SignedData.
// Parsing and signature verification do not establish trust in the TSA.
type TimeStampToken struct {
	SignedData       *SignedData
	Policy           asn1.ObjectIdentifier
	SerialNumber     *big.Int
	Time             time.Time
	ImprintAlgorithm asn1.ObjectIdentifier
	Imprint          []byte
	Nonce            *big.Int
}

func timestampHash(oid asn1.ObjectIdentifier) (hash.Hash, error) {
	switch {
	case oid.Equal(oidSHA256):
		return sha256.New(), nil
	case oid.Equal(oidSHA512):
		return sha512.New(), nil
	case oid.Equal(oidDigest256):
		return gost34112012256.New(), nil
	case oid.Equal(oidDigest512):
		return gost34112012512.New(), nil
	default:
		return nil, gostx509.ErrUnsupportedAlgorithm
	}
}

// CreateTimeStampRequest prepares an RFC 3161 request. The caller transports
// it to a TSA. certReq is set so the returned token can be checked locally.
func CreateTimeStampRequest(data []byte, digestOID asn1.ObjectIdentifier, nonce *big.Int) ([]byte, error) {
	h, err := timestampHash(digestOID)
	if err != nil {
		return nil, err
	}
	if nonce != nil && nonce.Sign() <= 0 {
		return nil, ErrTimeStamp
	}
	_, _ = h.Write(data)
	imprint := derWrap(0x30, algorithmDER(digestOID), derWrap(0x04, h.Sum(nil)))
	parts := [][]byte{{0x02, 0x01, 0x01}, imprint}
	if nonce != nil {
		parts = append(parts, mustASN1(nonce))
	}
	parts = append(parts, []byte{0x01, 0x01, 0xff})
	return derWrap(0x30, parts...), nil
}

// SignTimeStampToken creates an attached CMS time-stamp token for a TSA.
// imprint is the already-computed hash of the bytes being time-stamped.
func SignTimeStampToken(imprint []byte, digestOID, policy asn1.ObjectIdentifier, serial, nonce *big.Int, genTime time.Time, cert *gostx509.Certificate, signer crypto.Signer) ([]byte, error) {
	h, err := timestampHash(digestOID)
	if err != nil {
		return nil, err
	}
	if len(imprint) != h.Size() || len(policy) == 0 || serial == nil || serial.Sign() <= 0 || nonce != nil && nonce.Sign() <= 0 || genTime.IsZero() || genTime.Year() < 1970 || genTime.Year() > 9999 {
		return nil, ErrTimeStamp
	}
	if err := ValidateTSACertificate(cert); err != nil || genTime.Before(cert.NotBefore) || genTime.After(cert.NotAfter) {
		return nil, ErrTimeStamp
	}
	contentDigestOID, _, contentHash, err := signerProfile(cert, signer)
	if err != nil {
		return nil, err
	}
	info := [][]byte{
		{0x02, 0x01, 0x01}, derOID(policy),
		derWrap(0x30, algorithmDER(digestOID), derWrap(0x04, imprint)),
		mustASN1(serial), derWrap(0x18, []byte(genTime.UTC().Truncate(time.Second).Format("20060102150405Z"))),
	}
	if nonce != nil {
		info = append(info, mustASN1(nonce))
	}
	encoded := derWrap(0x30, info...)
	_, _ = contentHash.Write(encoded)
	return signHashed(encoded, true, cert, signer, contentDigestOID, oidTSTInfo, contentHash.Sum(nil))
}

// ValidateTSACertificate checks the RFC 3161 certificate role: a single,
// critical extendedKeyUsage extension containing only timeStamping. It does
// not verify certificate path trust, validity time, or revocation.
func ValidateTSACertificate(cert *gostx509.Certificate) error {
	if cert == nil || cert.KeyUsage != 0 && cert.KeyUsage&gostx509.KeyUsageDigitalSignature == 0 {
		return ErrTimeStamp
	}
	found := false
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidExtendedKeyUsage) {
			continue
		}
		if found || !ext.Critical {
			return ErrTimeStamp
		}
		found = true
		var usages []asn1.ObjectIdentifier
		if rest, err := asn1.Unmarshal(ext.Value, &usages); err != nil || len(rest) != 0 || len(usages) != 1 || !usages[0].Equal(oidTimeStampingUsage) {
			return ErrTimeStamp
		}
	}
	if !found {
		return ErrTimeStamp
	}
	return nil
}

// ParseTimeStampResponse parses an RFC 3161 response. A granted token is
// checked for its request nonce; signature and TSA trust are separate checks.
func ParseTimeStampResponse(der []byte, requestNonce *big.Int) (*TimeStampToken, error) {
	if len(der) == 0 || len(der) > maxCMSSize {
		return nil, ErrTimeStamp
	}
	_, body, tail, err := readExpected(der, 0x30)
	if err != nil || len(tail) != 0 {
		return nil, ErrTimeStamp
	}
	_, statusInfo, body, err := readExpected(body, 0x30)
	if err != nil {
		return nil, ErrTimeStamp
	}
	status, _, err := parseSmallInt(statusInfo)
	if err != nil || status > 5 {
		return nil, ErrTimeStamp
	}
	if status != 0 && status != 1 {
		return nil, fmt.Errorf("gogost/cms: Служба времени отклонила запрос со статусом %d", status)
	}
	if len(body) == 0 {
		return nil, ErrTimeStamp
	}
	full, _, rest, err := readExpected(body, 0x30)
	if err != nil || len(rest) != 0 {
		return nil, ErrTimeStamp
	}
	token, err := ParseTimeStampToken(full)
	if err != nil {
		return nil, err
	}
	if requestNonce != nil && (token.Nonce == nil || token.Nonce.Cmp(requestNonce) != 0) {
		return nil, ErrTimeStamp
	}
	return token, nil
}

// ParseTimeStampToken parses the CMS token and its TSTInfo. It does not
// verify its signature or authorize the TSA certificate.
func ParseTimeStampToken(der []byte) (*TimeStampToken, error) {
	return parseTimeStampToken(der, 0)
}

func parseTimeStampToken(der []byte, depth int) (*TimeStampToken, error) {
	signed, err := parseSignedData(der, depth)
	if err != nil || signed.Detached || !signed.ContentType.Equal(oidTSTInfo) || len(signed.Signers) != 1 || len(signed.Signers[0].signedAttrs) == 0 {
		return nil, ErrTimeStamp
	}
	content := signed.Content
	if content == nil {
		var size int
		for _, part := range signed.contentParts {
			size += len(part)
		}
		if size > 1<<20 {
			return nil, ErrTimeStamp
		}
		content = make([]byte, 0, size)
		for _, part := range signed.contentParts {
			content = append(content, part...)
		}
	}
	token, err := parseTSTInfo(content)
	if err != nil {
		return nil, err
	}
	token.SignedData = signed
	return token, nil
}

func parseTSTInfo(der []byte) (*TimeStampToken, error) {
	_, body, tail, err := readExpected(der, 0x30)
	if err != nil || len(tail) != 0 {
		return nil, ErrTimeStamp
	}
	version, body, err := parseSmallInt(body)
	if err != nil || version != 1 {
		return nil, ErrTimeStamp
	}
	policy, body, err := parseOID(body)
	if err != nil {
		return nil, ErrTimeStamp
	}
	_, imprint, body, err := readExpected(body, 0x30)
	if err != nil {
		return nil, ErrTimeStamp
	}
	algorithm, imprint, err := parseAlgorithm(imprint)
	if err != nil {
		return nil, ErrTimeStamp
	}
	h, err := timestampHash(algorithm)
	if err != nil {
		return nil, err
	}
	_, digest, tail, err := readExpected(imprint, 0x04)
	if err != nil || len(tail) != 0 || len(digest) != h.Size() {
		return nil, ErrTimeStamp
	}
	serialDER, _, rest, err := readExpected(body, 0x02)
	if err != nil {
		return nil, ErrTimeStamp
	}
	var serial *big.Int
	if extra, err := asn1.Unmarshal(serialDER, &serial); err != nil || len(extra) != 0 || serial == nil || serial.Sign() <= 0 {
		return nil, ErrTimeStamp
	}
	timeDER, _, body, err := readExpected(rest, 0x18)
	if err != nil {
		return nil, ErrTimeStamp
	}
	var generated time.Time
	if extra, err := asn1.Unmarshal(timeDER, &generated); err != nil || len(extra) != 0 {
		return nil, ErrTimeStamp
	}
	token := &TimeStampToken{Policy: policy, SerialNumber: serial, Time: generated, ImprintAlgorithm: algorithm, Imprint: digest}
	if len(body) > 0 && body[0] == 0x30 {
		_, _, body, err = readExpected(body, 0x30)
		if err != nil {
			return nil, ErrTimeStamp
		}
	} // accuracy
	if len(body) > 0 && body[0] == 0x01 {
		_, _, body, err = readExpected(body, 0x01)
		if err != nil {
			return nil, ErrTimeStamp
		}
	} // ordering
	if len(body) > 0 && body[0] == 0x02 {
		full, _, next, e := readExpected(body, 0x02)
		if e != nil {
			return nil, ErrTimeStamp
		}
		if extra, e := asn1.Unmarshal(full, &token.Nonce); e != nil || len(extra) != 0 || token.Nonce == nil || token.Nonce.Sign() <= 0 {
			return nil, ErrTimeStamp
		}
		body = next
	}
	if len(body) > 0 && body[0] == 0xa0 {
		_, _, body, err = readExpected(body, 0xa0)
		if err != nil {
			return nil, ErrTimeStamp
		}
	} // tsa
	if len(body) > 0 && body[0] == 0xa1 {
		_, _, body, err = readExpected(body, 0xa1)
		if err != nil {
			return nil, ErrTimeStamp
		}
	} // extensions
	if len(body) != 0 {
		return nil, ErrTimeStamp
	}
	return token, nil
}

// VerifyImprint checks that data is the exact material stamped by the TSA.
func (t *TimeStampToken) VerifyImprint(data []byte) error {
	if t == nil {
		return ErrTimeStamp
	}
	h, err := timestampHash(t.ImprintAlgorithm)
	if err != nil {
		return err
	}
	_, _ = h.Write(data)
	if !bytes.Equal(h.Sum(nil), t.Imprint) {
		return ErrTimeStamp
	}
	return nil
}

// VerifySignatures validates the CMS signature; certificate chain trust,
// TSA authorization, and revocation status remain caller decisions.
func (t *TimeStampToken) VerifySignatures() ([]SignerResult, error) {
	if t == nil || t.SignedData == nil {
		return nil, ErrTimeStamp
	}
	return t.SignedData.Verify(nil)
}

// ValidateTSASigner checks the token signer's certificate role and validity
// at genTime. Callers must still verify the certificate chain and revocation.
func (t *TimeStampToken) ValidateTSASigner() error {
	if t == nil || t.SignedData == nil || len(t.SignedData.Signers) != 1 {
		return ErrTimeStamp
	}
	cert := t.SignedData.Signers[0].Certificate
	if err := ValidateTSACertificate(cert); err != nil || t.Time.Before(cert.NotBefore) || t.Time.After(cert.NotAfter) {
		return ErrTimeStamp
	}
	return nil
}
