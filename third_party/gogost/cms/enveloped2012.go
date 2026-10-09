package cms

import (
	"crypto/rand"
	"encoding/asn1"
	"io"
	"math/big"

	"gitverse.ru/uzer_007/gogost/v3/gost3410"
	"gitverse.ru/uzer_007/gogost/v3/gost34112012256"
	"gitverse.ru/uzer_007/gogost/v3/gost3413/modes"
	"gitverse.ru/uzer_007/gogost/v3/gostx509"
	"gitverse.ru/uzer_007/gogost/v3/keywrap"
)

var (
	oidKuznechikCTRACPKM = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 5, 2, 1}
	oidMagmaCTRACPKM     = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 5, 1, 1}
	oidKuznechikKExp15   = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 7, 2, 1}
	oidMagmaKExp15       = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 7, 1, 1}
	oidAgreement256      = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 6, 1}
	oidAgreement512      = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 6, 2}
)

// EncryptEnveloped2012 creates RFC 5652 KeyAgreeRecipientInfo with an
// ephemeral originator key according to R 1323565.1.025-2019. algorithm
// selects Kuznechik or Magma for content encryption and KExp15 key transport.
// Content encryption has no authentication.
func EncryptEnveloped2012(content []byte, recipients []*gostx509.Certificate, algorithm keywrap.Algorithm) ([]byte, error) {
	if len(content) > maxCMSSize/2 || len(recipients) == 0 || len(recipients) > maxCMSCertificates {
		return nil, ErrEnvelopedData
	}
	contentOID, transportOID, ukmLen, ivLen, sectionSize, err := modernCipherParameters(algorithm)
	if err != nil {
		return nil, err
	}
	var cek [32]byte
	defer clear(cek[:])
	if _, err = io.ReadFull(rand.Reader, cek[:]); err != nil {
		return nil, err
	}
	contentUKM := make([]byte, ukmLen)
	if _, err = io.ReadFull(rand.Reader, contentUKM); err != nil {
		return nil, err
	}
	encodedRecipients := make([][]byte, 0, len(recipients))
	for _, recipient := range recipients {
		encoded, e := encryptModernRecipient(recipient, cek[:], algorithm, transportOID)
		if e != nil {
			return nil, e
		}
		encodedRecipients = append(encodedRecipients, encoded)
	}
	stream, err := modernContentStream(cek[:], contentUKM[:ivLen], algorithm, sectionSize)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	ciphertext, err := stream.Encrypt(nil, content)
	if err != nil {
		return nil, err
	}
	parameters := derWrap(0x30, derWrap(0x04, contentUKM))
	contentAlgorithm := derWrap(0x30, derOID(contentOID), parameters)
	eci := derWrap(0x30, derOID(oidData), contentAlgorithm, derWrap(0x80, ciphertext))
	enveloped := derWrap(0x30, []byte{0x02, 0x01, 0x02}, derSet(encodedRecipients...), eci)
	return derWrap(0x30, derOID(oidEnvelopedData), derWrap(0xa0, enveloped)), nil
}

// EncryptEnveloped2012To writes BER EnvelopedData in bounded content chunks.
// A failed read or write can leave a partial CMS object in w.
func EncryptEnveloped2012To(w io.Writer, content io.Reader, recipients []*gostx509.Certificate, algorithm keywrap.Algorithm) error {
	if w == nil || content == nil || len(recipients) == 0 || len(recipients) > maxCMSCertificates {
		return ErrEnvelopedData
	}
	contentOID, transportOID, ukmLen, ivLen, sectionSize, err := modernCipherParameters(algorithm)
	if err != nil {
		return err
	}
	var cek [32]byte
	defer clear(cek[:])
	if _, err := io.ReadFull(rand.Reader, cek[:]); err != nil {
		return err
	}
	contentUKM := make([]byte, ukmLen)
	if _, err := io.ReadFull(rand.Reader, contentUKM); err != nil {
		return err
	}
	encodedRecipients := make([][]byte, 0, len(recipients))
	for _, recipient := range recipients {
		encoded, err := encryptModernRecipient(recipient, cek[:], algorithm, transportOID)
		if err != nil {
			return err
		}
		encodedRecipients = append(encodedRecipients, encoded)
	}
	stream, err := modernContentStream(cek[:], contentUKM[:ivLen], algorithm, sectionSize)
	if err != nil {
		return err
	}
	defer stream.Close()
	contentAlgorithm := derWrap(0x30, derOID(contentOID), derWrap(0x30, derWrap(0x04, contentUKM)))
	prefix := [][]byte{
		{0x30, 0x80}, derOID(oidEnvelopedData), {0xa0, 0x80},
		{0x30, 0x80}, {0x02, 0x01, 0x02}, derSet(encodedRecipients...),
		{0x30, 0x80}, derOID(oidData), contentAlgorithm, {0xa0, 0x80},
	}
	for _, piece := range prefix {
		if err := writeCMS(w, piece); err != nil {
			return err
		}
	}
	var chunk [32 << 10]byte
	defer clear(chunk[:])
	var total int
	for {
		n, readErr := io.ReadFull(content, chunk[:])
		if n > 0 {
			if n > maxCMSSize/2-total {
				return ErrEnvelopedData
			}
			if _, err := stream.XORKeyStreamAt(chunk[:n], chunk[:n], total); err != nil {
				return err
			}
			if err := writeCMS(w, []byte{0x04}); err != nil {
				return err
			}
			if err := writeCMS(w, derLength(n)); err != nil {
				return err
			}
			if err := writeCMS(w, chunk[:n]); err != nil {
				return err
			}
			total += n
		}
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	for i := 0; i < 5; i++ {
		if err := writeCMS(w, []byte{0, 0}); err != nil {
			return err
		}
	}
	return nil
}

func modernCipherParameters(algorithm keywrap.Algorithm) (asn1.ObjectIdentifier, asn1.ObjectIdentifier, int, int, int, error) {
	switch algorithm {
	case keywrap.AlgorithmKuznechik:
		return oidKuznechikCTRACPKM, oidKuznechikKExp15, 16, 8, 256 << 10, nil
	case keywrap.AlgorithmMagma:
		return oidMagmaCTRACPKM, oidMagmaKExp15, 12, 4, 8 << 10, nil
	default:
		return nil, nil, 0, 0, 0, keywrap.ErrInvalidAlgorithm
	}
}

func modernContentStream(cek, iv []byte, algorithm keywrap.Algorithm, sectionSize int) (*modes.CTRACPKM, error) {
	switch algorithm {
	case keywrap.AlgorithmKuznechik:
		cipher, err := modes.NewKuznechik(cek)
		if err != nil {
			return nil, err
		}
		return cipher.CTRACPKM(iv, sectionSize)
	case keywrap.AlgorithmMagma:
		cipher, err := modes.NewMagma(cek)
		if err != nil {
			return nil, err
		}
		return cipher.CTRACPKM(iv, sectionSize)
	default:
		return nil, keywrap.ErrInvalidAlgorithm
	}
}

func encryptModernRecipient(cert *gostx509.Certificate, cek []byte, algorithm keywrap.Algorithm, transportOID asn1.ObjectIdentifier) ([]byte, error) {
	if cert == nil || cert.SerialNumber == nil || len(cert.RawIssuer) == 0 {
		return nil, ErrEnvelopedData
	}
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 15}) && cert.KeyUsage&gostx509.KeyUsageKeyAgreement == 0 {
			return nil, ErrEnvelopedData
		}
	}
	pub, ok := cert.PublicKey.(*gost3410.PublicKey)
	if !ok || pub == nil || pub.C == nil {
		return nil, gostx509.ErrUnsupportedAlgorithm
	}
	_, agreementOID, err := modernPublicAlgorithm(cert.RawSubjectPublicKeyInfo, pub.C.PointSize())
	if err != nil {
		return nil, err
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
	var ukm [32]byte
	if _, err = io.ReadFull(rand.Reader, ukm[:]); err != nil {
		return nil, err
	}
	keys, err := modernKEG(ephemeral, pub, ukm[:])
	if err != nil {
		return nil, err
	}
	defer clear(keys[:])
	ivLen := 8
	if algorithm == keywrap.AlgorithmMagma {
		ivLen = 4
	}
	wrapped, err := keywrap.KExp15(nil, cek, keys[:32], keys[32:], ukm[24:24+ivLen], algorithm)
	if err != nil {
		return nil, err
	}
	_, ephemeralSPKIBody, tail, err := readExpected(ephemeralSPKI, 0x30)
	if err != nil || len(tail) != 0 {
		return nil, ErrEnvelopedData
	}
	// RFC 5652 KeyAgreeRecipientInfo: originatorKey is an IMPLICIT
	// OriginatorPublicKey, so its body is the SPKI algorithm and BIT STRING.
	originator := derWrap(0xa0, derWrap(0xa1, ephemeralSPKIBody))
	keyAlgorithm := derWrap(0x30, derOID(transportOID), derWrap(0x30, derOID(agreementOID)))
	sid := derWrap(0x30, cert.RawIssuer, mustASN1(cert.SerialNumber))
	encryptedKey := derWrap(0x30, sid, derWrap(0x04, wrapped))
	return derWrap(0xa1, []byte{0x02, 0x01, 0x03}, originator,
		derWrap(0xa1, derWrap(0x04, ukm[:])), keyAlgorithm,
		derWrap(0x30, encryptedKey)), nil
}

func modernPublicAlgorithm(spkiDER []byte, pointSize int) (asn1.ObjectIdentifier, asn1.ObjectIdentifier, error) {
	_, spki, tail, err := readExpected(spkiDER, 0x30)
	if err != nil || len(tail) != 0 {
		return nil, nil, ErrEnvelopedData
	}
	_, algorithm, _, err := readExpected(spki, 0x30)
	if err != nil {
		return nil, nil, ErrEnvelopedData
	}
	publicOID, _, err := parseOID(algorithm)
	if err != nil {
		return nil, nil, ErrEnvelopedData
	}
	switch pointSize {
	case 32:
		if publicOID.Equal(oidPublicKey2012256) {
			return publicOID, oidAgreement256, nil
		}
	case 64:
		if publicOID.Equal(oidPublicKey2012512) {
			return publicOID, oidAgreement512, nil
		}
	}
	return nil, nil, gostx509.ErrUnsupportedAlgorithm
}

func modernKEG(private *gost3410.PrivateKey, public *gost3410.PublicKey, ukm []byte) ([64]byte, error) {
	var keys [64]byte
	if len(ukm) != 32 || private == nil || public == nil || private.C == nil || !private.C.Equal(public.C) {
		return keys, ErrEnvelopedData
	}
	r := new(big.Int).SetBytes(ukm[:16])
	if r.Sign() == 0 {
		r.SetInt64(1)
	}
	switch private.C.PointSize() {
	case 32:
		secret, err := private.KEK2012256(public, r)
		if err != nil {
			return keys, err
		}
		defer clear(secret)
		err = gost34112012256.NewKDF(secret).DeriveTreeInto(keys[:], []byte("kdf tree"), ukm[16:24], 1)
		return keys, err
	case 64:
		secret, err := private.KEK2012512(public, r)
		if err != nil {
			return keys, err
		}
		copy(keys[:], secret)
		clear(secret)
		return keys, nil
	default:
		return keys, gostx509.ErrUnsupportedAlgorithm
	}
}

func parseModernRecipient(recipient RecipientInfo, params, body []byte) (RecipientInfo, error) {
	_, params, rest, err := readExpected(params, 0x30)
	if err != nil || len(rest) != 0 {
		return recipient, ErrEnvelopedData
	}
	agreementOID, rest, err := parseOID(params)
	if err != nil || len(rest) != 0 || !agreementOID.Equal(oidAgreement256) && !agreementOID.Equal(oidAgreement512) {
		return recipient, gostx509.ErrUnsupportedAlgorithm
	}
	_, transportDER, rest, err := readExpected(body, 0x04)
	if err != nil || len(rest) != 0 {
		return recipient, ErrEnvelopedData
	}
	_, transport, rest, err := readExpected(transportDER, 0x30)
	if err != nil || len(rest) != 0 {
		return recipient, ErrEnvelopedData
	}
	_, recipient.encryptedKey, transport, err = readExpected(transport, 0x04)
	if err != nil {
		return recipient, ErrEnvelopedData
	}
	wantLen, wantPoint := 48, 32
	if recipient.keyOID.Equal(oidMagmaKExp15) {
		wantLen = 40
	}
	if agreementOID.Equal(oidAgreement512) {
		wantPoint = 64
	}
	if len(recipient.encryptedKey) != wantLen {
		return recipient, ErrEnvelopedData
	}
	recipient.ephemeralDER, _, transport, err = readExpected(transport, 0x30)
	if err != nil {
		return recipient, ErrEnvelopedData
	}
	_, recipient.UKM, transport, err = readExpected(transport, 0x04)
	if err != nil || len(transport) != 0 || len(recipient.UKM) != 32 {
		return recipient, ErrEnvelopedData
	}
	_, parsedAgreement, err := modernPublicAlgorithm(recipient.ephemeralDER, wantPoint)
	if err != nil || !parsedAgreement.Equal(agreementOID) {
		return recipient, ErrEnvelopedData
	}
	return recipient, nil
}

func (e *EnvelopedData) decryptModernTo(w io.Writer, recipient RecipientInfo, private *gost3410.PrivateKey) error {
	algorithm := keywrap.AlgorithmKuznechik
	if recipient.keyOID.Equal(oidMagmaKExp15) {
		algorithm = keywrap.AlgorithmMagma
	}
	contentOID, _, _, ivLen, sectionSize, _ := modernCipherParameters(algorithm)
	if !e.algorithm.Equal(contentOID) {
		return gostx509.ErrUnsupportedAlgorithm
	}
	ephemeralAny, err := gostx509.ParsePKIXPublicKey(recipient.ephemeralDER)
	if err != nil {
		return err
	}
	ephemeral, ok := ephemeralAny.(*gost3410.PublicKey)
	if !ok || !ephemeral.C.Equal(private.C) {
		return ErrEnvelopedData
	}
	keys, err := modernKEG(private, ephemeral, recipient.UKM)
	if err != nil {
		return err
	}
	defer clear(keys[:])
	cek, err := keywrap.KImp15(nil, recipient.encryptedKey, keys[:32], keys[32:], recipient.UKM[24:24+ivLen], algorithm)
	if err != nil {
		return err
	}
	defer clear(cek)
	stream, err := modernContentStream(cek, e.IV[:ivLen], algorithm, sectionSize)
	if err != nil {
		return err
	}
	defer stream.Close()
	parts := e.cipherParts
	if len(parts) == 0 {
		parts = [][]byte{e.Ciphertext}
	}
	var chunk [32 << 10]byte
	var offset int
	for _, part := range parts {
		for len(part) != 0 {
			n := min(len(part), len(chunk))
			if _, err := stream.XORKeyStreamAt(chunk[:n], part[:n], offset); err != nil {
				return err
			}
			if err := writeCMS(w, chunk[:n]); err != nil {
				return err
			}
			part = part[n:]
			offset += n
		}
	}
	clear(chunk[:])
	return nil
}
