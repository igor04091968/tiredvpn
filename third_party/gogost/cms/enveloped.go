package cms

import (
	"bytes"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"

	"gitverse.ru/uzer_007/gogost/v3/gost28147"
	"gitverse.ru/uzer_007/gogost/v3/gost3410"
	"gitverse.ru/uzer_007/gogost/v3/gostx509"
	"gitverse.ru/uzer_007/gogost/v3/keywrap"
)

var (
	oidEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidGOST2001Key   = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 19}
	oidGOST28147     = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 21}
	oidCryptoProA    = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 31, 1}
	oidCryptoProB    = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 31, 2}
	oidCryptoProC    = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 31, 3}
	oidCryptoProD    = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 31, 4}
	oidTC26Z         = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 5, 1, 1}

	ErrEnvelopedData = errors.New("gogost/cms: Некорректный EnvelopedData")
	ErrNoRecipient   = errors.New("gogost/cms: Получатель не найден")
)

// EnvelopedData is a CMS EnvelopedData value. Ciphertext and several nested
// byte strings reference the input passed to ParseEnvelopedData. Classic
// EnvelopedData provides no authentication of encrypted content.
type EnvelopedData struct {
	Recipients            []RecipientInfo
	Ciphertext            []byte
	IV                    []byte
	UnprotectedAttributes []byte // encoded [1] IMPLICIT SET OF; references the parse input
	cipherParts           [][]byte
	algorithm             asn1.ObjectIdentifier
	contentSbox           *gost28147.Sbox
}

// RecipientInfo identifies a KeyTransRecipientInfo or KeyAgreeRecipientInfo.
type RecipientInfo struct {
	Issuer       []byte
	SerialNumber *big.Int
	SubjectKeyID []byte
	UKM          []byte
	ephemeralDER []byte
	encryptedKey []byte
	mac          []byte
	algorithmDER []byte
	keyOID       asn1.ObjectIdentifier
	wrapSbox     *gost28147.Sbox
}

// LegacyParamSet selects a published GOST 28147-89 parameter set for legacy
// CMS content encryption and CryptoPro key transport. The zero value is A.
type LegacyParamSet uint8

const (
	LegacyCryptoProA LegacyParamSet = iota
	LegacyCryptoProB
	LegacyCryptoProC
	LegacyCryptoProD
	LegacyTC26Z
)

func legacyParam(param LegacyParamSet) (asn1.ObjectIdentifier, *gost28147.Sbox, error) {
	switch param {
	case LegacyCryptoProA:
		return oidCryptoProA, &gost28147.SboxIdGost2814789CryptoProAParamSet, nil
	case LegacyCryptoProB:
		return oidCryptoProB, &gost28147.SboxIdGost2814789CryptoProBParamSet, nil
	case LegacyCryptoProC:
		return oidCryptoProC, &gost28147.SboxIdGost2814789CryptoProCParamSet, nil
	case LegacyCryptoProD:
		return oidCryptoProD, &gost28147.SboxIdGost2814789CryptoProDParamSet, nil
	case LegacyTC26Z:
		return oidTC26Z, &gost28147.SboxIdtc26gost28147paramZ, nil
	default:
		return nil, nil, gostx509.ErrUnsupportedAlgorithm
	}
}

func legacySbox(oid asn1.ObjectIdentifier) (*gost28147.Sbox, error) {
	for param := LegacyCryptoProA; param <= LegacyTC26Z; param++ {
		candidate, sbox, _ := legacyParam(param)
		if oid.Equal(candidate) {
			return sbox, nil
		}
	}
	return nil, gostx509.ErrUnsupportedAlgorithm
}

// EncryptEnveloped creates RFC 5652 / RFC 4490 DER EnvelopedData with GOST
// R 34.10-2001 key transport and GOST 28147-89 CryptoPro-A content encryption.
// All recipients receive the same random CEK through independent ephemeral
// key transports.
func EncryptEnveloped(content []byte, recipients []*gostx509.Certificate) ([]byte, error) {
	return encryptEnvelopedLegacy(content, recipients, false, LegacyCryptoProA)
}

// EncryptEnvelopedLegacy permits GOST R 34.10-2012 recipients with the
// GOST 28147-89/CryptoPro-A transport profile as well as 2001 recipients.
// Use EncryptEnveloped2012 for the current KExp15/CTR-ACPKM profile.
func EncryptEnvelopedLegacy(content []byte, recipients []*gostx509.Certificate) ([]byte, error) {
	return encryptEnvelopedLegacy(content, recipients, true, LegacyCryptoProA)
}

// EncryptEnvelopedLegacyWithParamSet selects A, B, C, D, or TC26 Z explicitly.
func EncryptEnvelopedLegacyWithParamSet(content []byte, recipients []*gostx509.Certificate, paramSet LegacyParamSet) ([]byte, error) {
	return encryptEnvelopedLegacy(content, recipients, true, paramSet)
}

func encryptEnvelopedLegacy(content []byte, recipients []*gostx509.Certificate, allow2012 bool, paramSet LegacyParamSet) ([]byte, error) {
	paramOID, sbox, err := legacyParam(paramSet)
	if err != nil {
		return nil, err
	}
	if len(content) > maxCMSSize/2 || len(recipients) == 0 || len(recipients) > maxCMSCertificates {
		return nil, ErrEnvelopedData
	}
	var cek [32]byte
	var iv [8]byte
	if _, err := io.ReadFull(rand.Reader, cek[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, iv[:]); err != nil {
		return nil, err
	}
	encodedRecipients := make([][]byte, 0, len(recipients))
	for _, recipient := range recipients {
		encoded, err := encryptRecipient(recipient, cek[:], allow2012, paramOID, sbox)
		if err != nil {
			return nil, err
		}
		encodedRecipients = append(encodedRecipients, encoded)
	}
	ciphertext := make([]byte, len(content))
	stream, err := gost28147.NewMeshedCFBEncrypter(cek[:], sbox, iv[:])
	if err != nil {
		return nil, err
	}
	stream.XORKeyStream(ciphertext, content)
	parameters := derWrap(0x30, derWrap(0x04, iv[:]), derOID(paramOID))
	contentAlgorithm := derWrap(0x30, derOID(oidGOST28147), parameters)
	eci := derWrap(0x30, derOID(oidData), contentAlgorithm, derWrap(0x80, ciphertext))
	enveloped := derWrap(0x30, []byte{0x02, 0x01, 0x00}, derSet(encodedRecipients...), eci)
	return derWrap(0x30, derOID(oidEnvelopedData), derWrap(0xa0, enveloped)), nil
}

// EncryptEnvelopedTo streams BER EnvelopedData to w. Memory use is bounded by
// the recipient set and a 32 KiB content chunk. On write or read failure, w
// may contain a partial CMS object.
func EncryptEnvelopedTo(w io.Writer, content io.Reader, recipients []*gostx509.Certificate) error {
	if w == nil || content == nil || len(recipients) == 0 || len(recipients) > maxCMSCertificates {
		return ErrEnvelopedData
	}
	var cek [32]byte
	var iv [8]byte
	if _, err := io.ReadFull(rand.Reader, cek[:]); err != nil {
		return err
	}
	if _, err := io.ReadFull(rand.Reader, iv[:]); err != nil {
		return err
	}
	encodedRecipients := make([][]byte, 0, len(recipients))
	for _, recipient := range recipients {
		encoded, err := encryptRecipient(recipient, cek[:], false, oidCryptoProA, &gost28147.SboxIdGost2814789CryptoProAParamSet)
		if err != nil {
			return err
		}
		encodedRecipients = append(encodedRecipients, encoded)
	}
	parameters := derWrap(0x30, derWrap(0x04, iv[:]), derOID(oidCryptoProA))
	contentAlgorithm := derWrap(0x30, derOID(oidGOST28147), parameters)
	prefix := [][]byte{
		{0x30, 0x80}, derOID(oidEnvelopedData), {0xa0, 0x80},
		{0x30, 0x80}, {0x02, 0x01, 0x00}, derSet(encodedRecipients...),
		{0x30, 0x80}, derOID(oidData), contentAlgorithm, {0xa0, 0x80},
	}
	for _, piece := range prefix {
		if err := writeCMS(w, piece); err != nil {
			return err
		}
	}
	stream, err := gost28147.NewMeshedCFBEncrypter(cek[:], &gost28147.SboxIdGost2814789CryptoProAParamSet, iv[:])
	if err != nil {
		return err
	}
	var chunk [32 << 10]byte
	var total int64
	for {
		n, err := io.ReadFull(content, chunk[:])
		if n > 0 {
			total += int64(n)
			if total > maxCMSSize/2 {
				return ErrEnvelopedData
			}
			stream.XORKeyStream(chunk[:n], chunk[:n])
			if e := writeCMS(w, []byte{0x04}); e != nil {
				return e
			}
			if e := writeCMS(w, derLength(n)); e != nil {
				return e
			}
			if e := writeCMS(w, chunk[:n]); e != nil {
				return e
			}
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return err
		}
	}
	for i := 0; i < 5; i++ {
		if err := writeCMS(w, []byte{0, 0}); err != nil {
			return err
		}
	}
	return nil
}

func writeCMS(w io.Writer, p []byte) error {
	n, err := w.Write(p)
	if err != nil {
		return err
	}
	if n != len(p) {
		return io.ErrShortWrite
	}
	return nil
}

func encryptRecipient(cert *gostx509.Certificate, cek []byte, allow2012 bool, paramOID asn1.ObjectIdentifier, sbox *gost28147.Sbox) ([]byte, error) {
	if cert == nil || cert.SerialNumber == nil || len(cert.RawIssuer) == 0 {
		return nil, ErrEnvelopedData
	}
	pub, ok := cert.PublicKey.(*gost3410.PublicKey)
	if !ok || pub == nil || pub.C == nil {
		return nil, gostx509.ErrUnsupportedAlgorithm
	}
	spkiDER := cert.RawSubjectPublicKeyInfo
	if len(spkiDER) == 0 {
		var err error
		spkiDER, err = gostx509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return nil, err
		}
	}
	_, spki, tail, err := readExpected(spkiDER, 0x30)
	if err != nil || len(tail) != 0 {
		return nil, ErrEnvelopedData
	}
	algorithmDER, algorithmBody, _, err := readExpected(spki, 0x30)
	if err != nil {
		return nil, ErrEnvelopedData
	}
	keyOID, _, err := parseOID(algorithmBody)
	if err != nil || (!keyOID.Equal(oidGOST2001Key) && !(allow2012 && (keyOID.Equal(oidPublicKey2012256) || keyOID.Equal(oidPublicKey2012512)))) {
		return nil, gostx509.ErrUnsupportedAlgorithm
	}
	if keyOID.Equal(oidGOST2001Key) && (pub.C.PointSize() != 32 || !is2001Curve(pub.C.Name)) {
		return nil, gostx509.ErrUnsupportedAlgorithm
	}
	if keyOID.Equal(oidPublicKey2012256) && pub.C.PointSize() != 32 || keyOID.Equal(oidPublicKey2012512) && pub.C.PointSize() != 64 {
		return nil, gostx509.ErrUnsupportedAlgorithm
	}
	ephemeral, err := gost3410.GenPrivateKey(pub.C, rand.Reader)
	if err != nil {
		return nil, err
	}
	ephemeralPub, err := ephemeral.PublicKey()
	if err != nil {
		return nil, err
	}
	ephemeralSPKI, err := gostx509.MarshalPKIXPublicKey(ephemeralPub)
	if err != nil {
		return nil, err
	}
	_, ephemeralBody, _, err := readExpected(ephemeralSPKI, 0x30)
	if err != nil {
		return nil, err
	}
	_, _, ephemeralBody, err = readExpected(ephemeralBody, 0x30)
	if err != nil || len(ephemeralBody) == 0 || ephemeralBody[0] != 0x03 {
		return nil, ErrEnvelopedData
	}
	ephemeralBody = append(append([]byte(nil), algorithmDER...), ephemeralBody...)
	var ukm [8]byte
	if _, err = io.ReadFull(rand.Reader, ukm[:]); err != nil {
		return nil, err
	}
	var kek []byte
	if keyOID.Equal(oidGOST2001Key) {
		kek, err = ephemeral.KEK2001(pub, gost3410.NewUKM(ukm[:]))
	} else {
		kek, err = ephemeral.KEK2012256(pub, gost3410.NewUKM(ukm[:]))
	}
	if err != nil {
		return nil, err
	}
	wrapped, err := keywrap.WrapCryptoProWithSbox(nil, ukm[:], kek, cek, sbox)
	if err != nil {
		return nil, err
	}
	sessionKey := derWrap(0x30,
		derWrap(0x04, wrapped[8:40]), derWrap(0x04, wrapped[40:44]))
	transportParams := derWrap(0xa0, derOID(paramOID),
		derWrap(0xa0, ephemeralBody), derWrap(0x04, ukm[:]))
	transport := derWrap(0x30, sessionKey, transportParams)
	sid := derWrap(0x30, cert.RawIssuer, mustASN1(cert.SerialNumber))
	return derWrap(0x30, []byte{0x02, 0x01, 0x00}, sid,
		algorithmDER, derWrap(0x04, transport)), nil
}

func is2001Curve(name string) bool { return bytes.Contains([]byte(name), []byte("2001")) }

// ParseEnvelopedData parses DER CMS EnvelopedData with bounded recipient count
// and explicit rejection of unsupported content encryption algorithms.
func ParseEnvelopedData(der []byte) (*EnvelopedData, error) {
	if len(der) == 0 || len(der) > maxCMSSize {
		return nil, ErrEnvelopedData
	}
	_, outer, tail, err := readExpectedBER(der, 0x30)
	if err != nil || len(tail) != 0 {
		return nil, ErrEnvelopedData
	}
	oid, outer, err := parseOID(outer)
	if err != nil || !oid.Equal(oidEnvelopedData) {
		return nil, ErrEnvelopedData
	}
	_, explicit, tail, err := readExpectedBER(outer, 0xa0)
	if err != nil || len(tail) != 0 {
		return nil, ErrEnvelopedData
	}
	_, body, tail, err := readExpectedBER(explicit, 0x30)
	if err != nil || len(tail) != 0 {
		return nil, ErrEnvelopedData
	}
	version, body, err := parseSmallInt(body)
	if err != nil || version != 0 && version != 2 {
		return nil, ErrEnvelopedData
	}
	var originators []*gostx509.Certificate
	if version == 2 && len(body) != 0 && body[0] == 0xa0 {
		var originatorInfo []byte
		_, originatorInfo, body, err = readExpected(body, 0xa0)
		if err != nil {
			return nil, ErrEnvelopedData
		}
		var certificates []byte
		_, certificates, originatorInfo, err = readExpected(originatorInfo, 0xa0)
		if err != nil || len(originatorInfo) != 0 {
			return nil, ErrEnvelopedData
		}
		for len(certificates) != 0 {
			if len(originators) >= maxCMSCertificates {
				return nil, ErrEnvelopedData
			}
			var certificateDER []byte
			certificateDER, _, certificates, err = readExpected(certificates, 0x30)
			if err != nil {
				return nil, ErrEnvelopedData
			}
			certificate, err := gostx509.ParseCertificate(certificateDER)
			if err != nil {
				return nil, fmt.Errorf("%w: originator certificate: %v", ErrEnvelopedData, err)
			}
			originators = append(originators, certificate)
		}
	}
	_, recips, body, err := readExpectedBER(body, 0x31)
	if err != nil || len(recips) == 0 {
		return nil, ErrEnvelopedData
	}
	result := &EnvelopedData{}
	entryCount := 0
	for len(recips) != 0 {
		entryCount++
		if entryCount > maxCMSCertificates || len(result.Recipients) >= maxCMSCertificates {
			return nil, ErrEnvelopedData
		}
		tag, _, recipientBody, next, e := readBER(recips, 0)
		if e != nil || len(recipientBody) == 0 {
			return nil, ErrEnvelopedData
		}
		switch tag {
		case 0xa1:
			parsed, e := parseKeyAgreeRecipients(recipientBody, originators)
			if errors.Is(e, gostx509.ErrUnsupportedAlgorithm) {
				break
			}
			if e != nil || len(result.Recipients)+len(parsed) > maxCMSCertificates {
				return nil, ErrEnvelopedData
			}
			result.Recipients = append(result.Recipients, parsed...)
		case 0x30:
			recipient, e := parseRecipient(recipientBody)
			if errors.Is(e, gostx509.ErrUnsupportedAlgorithm) {
				break
			}
			if e != nil {
				return nil, e
			}
			result.Recipients = append(result.Recipients, recipient)
		case 0xa2, 0xa3, 0xa4:
			// Other valid RecipientInfo choices can coexist with a recipient
			// this implementation can decrypt.
		default:
			return nil, ErrEnvelopedData
		}
		recips = next
	}
	if len(result.Recipients) == 0 {
		return nil, gostx509.ErrUnsupportedAlgorithm
	}
	_, encryptedInfo, tail, err := readExpectedBER(body, 0x30)
	if err != nil {
		return nil, ErrEnvelopedData
	}
	if len(tail) != 0 {
		var attrs []byte
		result.UnprotectedAttributes, attrs, tail, err = readExpectedBER(tail, 0xa1)
		if err != nil || len(tail) != 0 || validateUnprotectedAttrs(attrs) != nil {
			return nil, ErrEnvelopedData
		}
	}
	contentOID, encryptedInfo, err := parseOID(encryptedInfo)
	if err != nil || !contentOID.Equal(oidData) {
		return nil, ErrEnvelopedData
	}
	_, algorithmBody, encryptedInfo, err := readExpected(encryptedInfo, 0x30)
	if err != nil {
		return nil, ErrEnvelopedData
	}
	contentAlgorithm, algorithmBody, err := parseOID(algorithmBody)
	if err != nil {
		return nil, ErrEnvelopedData
	}
	result.algorithm = contentAlgorithm
	if !contentAlgorithm.Equal(oidGOST28147) && !contentAlgorithm.Equal(oidKuznechikCTRACPKM) && !contentAlgorithm.Equal(oidMagmaCTRACPKM) {
		return nil, gostx509.ErrUnsupportedAlgorithm
	}
	_, params, algorithmBody, err := readExpected(algorithmBody, 0x30)
	if err != nil || len(algorithmBody) != 0 {
		return nil, ErrEnvelopedData
	}
	if contentAlgorithm.Equal(oidGOST28147) {
		_, result.IV, params, err = readExpected(params, 0x04)
		if err != nil || len(result.IV) != 8 {
			return nil, ErrEnvelopedData
		}
		paramSet, rest, e := parseOID(params)
		if e != nil || len(rest) != 0 {
			return nil, ErrEnvelopedData
		}
		result.contentSbox, err = legacySbox(paramSet)
		if err != nil {
			return nil, err
		}
	} else {
		_, result.IV, params, err = readExpected(params, 0x04)
		ukmLen := 16
		if contentAlgorithm.Equal(oidMagmaCTRACPKM) {
			ukmLen = 12
		}
		if err != nil || len(params) != 0 || len(result.IV) != ukmLen {
			return nil, ErrEnvelopedData
		}
	}
	tag, _, octets, rest, err := readBER(encryptedInfo, 0)
	if err != nil || len(rest) != 0 {
		return nil, ErrEnvelopedData
	}
	result.cipherParts, err = octetSegments(tag, octets, 0, nil)
	if err != nil {
		return nil, ErrEnvelopedData
	}
	if len(result.cipherParts) == 1 {
		result.Ciphertext = result.cipherParts[0]
	}
	return result, nil
}

func validateUnprotectedAttrs(attrs []byte) error {
	count := 0
	for len(attrs) != 0 {
		count++
		if count > maxCMSCertificates {
			return ErrEnvelopedData
		}
		_, body, rest, err := readExpectedBER(attrs, 0x30)
		if err != nil {
			return ErrEnvelopedData
		}
		_, body, err = parseOID(body)
		if err != nil {
			return ErrEnvelopedData
		}
		_, values, tail, err := readExpectedBER(body, 0x31)
		if err != nil || len(tail) != 0 || len(values) == 0 {
			return ErrEnvelopedData
		}
		valueCount := 0
		for len(values) != 0 {
			valueCount++
			if valueCount > maxCMSCertificates {
				return ErrEnvelopedData
			}
			_, _, _, values, err = readBER(values, 0)
			if err != nil {
				return ErrEnvelopedData
			}
		}
		attrs = rest
	}
	return nil
}

func parseRecipient(body []byte) (RecipientInfo, error) {
	var recipient RecipientInfo
	version, body, err := parseSmallInt(body)
	if err != nil || version != 0 && version != 2 {
		return recipient, ErrEnvelopedData
	}
	if version == 0 {
		var sid []byte
		_, sid, body, err = readExpected(body, 0x30)
		if err != nil {
			return recipient, ErrEnvelopedData
		}
		recipient.Issuer, _, sid, err = readExpected(sid, 0x30)
		if err != nil {
			return recipient, ErrEnvelopedData
		}
		serialDER, _, rest, e := readExpected(sid, 0x02)
		if e != nil || len(rest) != 0 {
			return recipient, ErrEnvelopedData
		}
		if _, err = asn1.Unmarshal(serialDER, &recipient.SerialNumber); err != nil || recipient.SerialNumber == nil || recipient.SerialNumber.Sign() <= 0 {
			return recipient, ErrEnvelopedData
		}
	} else {
		_, recipient.SubjectKeyID, body, err = readExpected(body, 0x80)
		if err != nil || len(recipient.SubjectKeyID) == 0 {
			return recipient, ErrEnvelopedData
		}
	}
	recipient.algorithmDER, _, body, err = readExpected(body, 0x30)
	if err != nil {
		return recipient, ErrEnvelopedData
	}
	_, algorithmBody, _, _ := readExpected(recipient.algorithmDER, 0x30)
	keyOID, keyParams, e := parseOID(algorithmBody)
	if e != nil {
		return recipient, ErrEnvelopedData
	}
	recipient.keyOID = keyOID
	if keyOID.Equal(oidKuznechikKExp15) || keyOID.Equal(oidMagmaKExp15) {
		return parseModernRecipient(recipient, keyParams, body)
	}
	if !keyOID.Equal(oidGOST2001Key) && !keyOID.Equal(oidPublicKey2012256) && !keyOID.Equal(oidPublicKey2012512) {
		return recipient, gostx509.ErrUnsupportedAlgorithm
	}
	if version != 0 {
		return recipient, gostx509.ErrUnsupportedAlgorithm
	}
	_, transportDER, body, err := readExpected(body, 0x04)
	if err != nil || len(body) != 0 {
		return recipient, ErrEnvelopedData
	}
	_, transport, tail, err := readExpected(transportDER, 0x30)
	if err != nil || len(tail) != 0 {
		return recipient, ErrEnvelopedData
	}
	_, encrypted, transport, err := readExpected(transport, 0x30)
	if err != nil {
		return recipient, ErrEnvelopedData
	}
	_, recipient.encryptedKey, encrypted, err = readExpected(encrypted, 0x04)
	if err != nil || len(recipient.encryptedKey) != 32 {
		return recipient, ErrEnvelopedData
	}
	_, recipient.mac, encrypted, err = readExpected(encrypted, 0x04)
	if err != nil || len(recipient.mac) != 4 || len(encrypted) != 0 {
		return recipient, ErrEnvelopedData
	}
	_, params, transport, err := readExpected(transport, 0xa0)
	if err != nil || len(transport) != 0 {
		return recipient, ErrEnvelopedData
	}
	paramSet, params, err := parseOID(params)
	if err != nil {
		return recipient, ErrEnvelopedData
	}
	recipient.wrapSbox, err = legacySbox(paramSet)
	if err != nil {
		return recipient, err
	}
	_, ephemeralBody, params, err := readExpected(params, 0xa0)
	if err != nil {
		return recipient, ErrEnvelopedData
	}
	recipient.ephemeralDER = derWrap(0x30, ephemeralBody)
	_, recipient.UKM, params, err = readExpected(params, 0x04)
	if err != nil || len(params) != 0 || len(recipient.UKM) != 8 {
		return recipient, ErrEnvelopedData
	}
	return recipient, nil
}

// DecryptUnauthenticatedTo writes decrypted content for the matching
// recipient. A successful return authenticates only the wrapped CEK, not the
// encrypted content; callers must verify a signature where integrity matters.
func (e *EnvelopedData) DecryptUnauthenticatedTo(w io.Writer, cert *gostx509.Certificate, private *gost3410.PrivateKey) error {
	if e == nil || w == nil || cert == nil || private == nil || private.C == nil || cert.SerialNumber == nil {
		return ErrEnvelopedData
	}
	pub, ok := cert.PublicKey.(*gost3410.PublicKey)
	if !ok || !pub.C.Equal(private.C) {
		return gostx509.ErrUnsupportedAlgorithm
	}
	derivedPub, err := private.PublicKey()
	if err != nil || !pub.Equal(derivedPub) {
		return ErrNoRecipient
	}
	for _, recipient := range e.Recipients {
		match := len(recipient.SubjectKeyID) != 0 && bytes.Equal(recipient.SubjectKeyID, cert.SubjectKeyId)
		if len(recipient.SubjectKeyID) == 0 {
			match = bytes.Equal(recipient.Issuer, cert.RawIssuer) && recipient.SerialNumber != nil && recipient.SerialNumber.Cmp(cert.SerialNumber) == 0
		}
		if !match {
			continue
		}
		if recipient.keyOID.Equal(oidKuznechikKExp15) || recipient.keyOID.Equal(oidMagmaKExp15) {
			return e.decryptModernTo(w, recipient, private)
		}
		if !e.algorithm.Equal(oidGOST28147) ||
			(recipient.keyOID.Equal(oidGOST2001Key) && !is2001Curve(private.C.Name)) ||
			(!recipient.keyOID.Equal(oidGOST2001Key) && !recipient.keyOID.Equal(oidPublicKey2012256) && !recipient.keyOID.Equal(oidPublicKey2012512)) {
			return gostx509.ErrUnsupportedAlgorithm
		}
		spki := cert.RawSubjectPublicKeyInfo
		_, spkiBody, _, err := readExpected(spki, 0x30)
		if err != nil {
			return ErrEnvelopedData
		}
		algorithmDER, _, _, err := readExpected(spkiBody, 0x30)
		if err != nil || !bytes.Equal(algorithmDER, recipient.algorithmDER) {
			return ErrEnvelopedData
		}
		ephemeralAny, err := gostx509.ParsePKIXPublicKey(recipient.ephemeralDER)
		if err != nil {
			return err
		}
		ephemeral, ok := ephemeralAny.(*gost3410.PublicKey)
		if !ok || !ephemeral.C.Equal(private.C) {
			return ErrEnvelopedData
		}
		var kek []byte
		if recipient.keyOID.Equal(oidGOST2001Key) {
			kek, err = private.KEK2001(ephemeral, gost3410.NewUKM(recipient.UKM))
		} else {
			kek, err = private.KEK2012256(ephemeral, gost3410.NewUKM(recipient.UKM))
		}
		if err != nil {
			return err
		}
		wrapped := make([]byte, 0, 44)
		wrapped = append(wrapped, recipient.UKM...)
		wrapped = append(wrapped, recipient.encryptedKey...)
		wrapped = append(wrapped, recipient.mac...)
		cek, err := keywrap.UnwrapCryptoProWithSbox(nil, kek, wrapped, recipient.wrapSbox)
		if err != nil {
			return err
		}
		stream, err := gost28147.NewMeshedCFBDecrypter(cek, e.contentSbox, e.IV)
		if err != nil {
			return err
		}
		var chunk [32 << 10]byte
		parts := e.cipherParts
		if len(parts) == 0 {
			parts = [][]byte{e.Ciphertext}
		}
		for _, part := range parts {
			for offset := 0; offset < len(part); {
				n := copy(chunk[:], part[offset:])
				stream.XORKeyStream(chunk[:n], chunk[:n])
				written, err := w.Write(chunk[:n])
				if err != nil {
					return err
				}
				if written != n {
					return io.ErrShortWrite
				}
				offset += n
			}
		}
		return nil
	}
	return ErrNoRecipient
}

// DecryptUnauthenticated returns plaintext in memory for small CMS messages.
func (e *EnvelopedData) DecryptUnauthenticated(cert *gostx509.Certificate, private *gost3410.PrivateKey) ([]byte, error) {
	var out bytes.Buffer
	if err := e.DecryptUnauthenticatedTo(&out, cert, private); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
