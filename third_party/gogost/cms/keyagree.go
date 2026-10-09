package cms

import (
	"bytes"
	"encoding/asn1"
	"math/big"

	"gitverse.ru/uzer_007/gogost/v3/gostx509"
)

// parseKeyAgreeRecipients handles RFC 5652 KeyAgreeRecipientInfo. The
// originator may be an embedded public key or a certificate selected from
// OriginatorInfo. Neither form establishes trust by itself.
func parseKeyAgreeRecipients(body []byte, originators []*gostx509.Certificate) ([]RecipientInfo, error) {
	version, body, err := parseSmallInt(body)
	if err != nil || version != 3 {
		return nil, ErrEnvelopedData
	}
	var originator []byte
	_, originator, body, err = readExpected(body, 0xa0)
	if err != nil || len(originator) == 0 {
		return nil, ErrEnvelopedData
	}
	var publicDER []byte
	switch originator[0] {
	case 0xa1: // OriginatorPublicKey, IMPLICIT SubjectPublicKeyInfo
		_, publicDER, originator, err = readExpected(originator, 0xa1)
		if err != nil || len(originator) != 0 {
			return nil, ErrEnvelopedData
		}
		publicDER = derWrap(0x30, publicDER)
	case 0x30: // issuerAndSerialNumber
		var identifier []byte
		_, identifier, originator, err = readExpected(originator, 0x30)
		if err != nil || len(originator) != 0 {
			return nil, ErrEnvelopedData
		}
		var issuer []byte
		issuer, _, identifier, err = readExpected(identifier, 0x30)
		if err != nil {
			return nil, ErrEnvelopedData
		}
		var serial *big.Int
		var serialDER []byte
		serialDER, _, identifier, err = readExpected(identifier, 0x02)
		if err != nil || len(identifier) != 0 {
			return nil, ErrEnvelopedData
		}
		if _, err = asn1.Unmarshal(serialDER, &serial); err != nil || serial == nil || serial.Sign() <= 0 {
			return nil, ErrEnvelopedData
		}
		for _, certificate := range originators {
			if bytes.Equal(certificate.RawIssuer, issuer) && certificate.SerialNumber.Cmp(serial) == 0 {
				publicDER = certificate.RawSubjectPublicKeyInfo
				break
			}
		}
		if len(publicDER) == 0 {
			return nil, ErrEnvelopedData
		}
	default:
		return nil, ErrEnvelopedData
	}
	if len(body) == 0 || body[0] != 0xa1 {
		return nil, ErrEnvelopedData
	}
	var ukmExplicit []byte
	_, ukmExplicit, body, err = readExpected(body, 0xa1)
	if err != nil {
		return nil, ErrEnvelopedData
	}
	var ukm []byte
	_, ukm, ukmExplicit, err = readExpected(ukmExplicit, 0x04)
	if err != nil || len(ukmExplicit) != 0 || len(ukm) != 32 {
		return nil, ErrEnvelopedData
	}
	var algorithm []byte
	_, algorithm, body, err = readExpected(body, 0x30)
	if err != nil {
		return nil, ErrEnvelopedData
	}
	keyOID, params, err := parseOID(algorithm)
	if err != nil || !keyOID.Equal(oidKuznechikKExp15) && !keyOID.Equal(oidMagmaKExp15) {
		return nil, gostx509.ErrUnsupportedAlgorithm
	}
	var agreementParams []byte
	_, agreementParams, params, err = readExpected(params, 0x30)
	if err != nil || len(params) != 0 {
		return nil, ErrEnvelopedData
	}
	agreementOID, rest, err := parseOID(agreementParams)
	if err != nil || len(rest) != 0 || !agreementOID.Equal(oidAgreement256) && !agreementOID.Equal(oidAgreement512) {
		return nil, gostx509.ErrUnsupportedAlgorithm
	}
	pointSize := 32
	if agreementOID.Equal(oidAgreement512) {
		pointSize = 64
	}
	_, parsedAgreement, err := modernPublicAlgorithm(publicDER, pointSize)
	if err != nil || !parsedAgreement.Equal(agreementOID) {
		return nil, ErrEnvelopedData
	}
	var keys []byte
	_, keys, body, err = readExpected(body, 0x30)
	if err != nil || len(body) != 0 || len(keys) == 0 {
		return nil, ErrEnvelopedData
	}
	var recipients []RecipientInfo
	for len(keys) != 0 {
		if len(recipients) >= maxCMSCertificates {
			return nil, ErrEnvelopedData
		}
		var entry []byte
		_, entry, keys, err = readExpected(keys, 0x30)
		if err != nil {
			return nil, ErrEnvelopedData
		}
		recipient := RecipientInfo{UKM: ukm, ephemeralDER: publicDER, keyOID: keyOID}
		if len(entry) == 0 {
			return nil, ErrEnvelopedData
		}
		switch entry[0] {
		case 0x30:
			var identifier []byte
			_, identifier, entry, err = readExpected(entry, 0x30)
			if err != nil {
				return nil, ErrEnvelopedData
			}
			recipient.Issuer, _, identifier, err = readExpected(identifier, 0x30)
			if err != nil {
				return nil, ErrEnvelopedData
			}
			var serialDER []byte
			serialDER, _, identifier, err = readExpected(identifier, 0x02)
			if err != nil || len(identifier) != 0 {
				return nil, ErrEnvelopedData
			}
			if _, err = asn1.Unmarshal(serialDER, &recipient.SerialNumber); err != nil || recipient.SerialNumber == nil || recipient.SerialNumber.Sign() <= 0 {
				return nil, ErrEnvelopedData
			}
		case 0xa0:
			var recipientKeyID []byte
			_, recipientKeyID, entry, err = readExpected(entry, 0xa0)
			if err != nil {
				return nil, ErrEnvelopedData
			}
			_, recipient.SubjectKeyID, recipientKeyID, err = readExpected(recipientKeyID, 0x04)
			if err != nil || len(recipientKeyID) != 0 || len(recipient.SubjectKeyID) == 0 {
				return nil, ErrEnvelopedData
			}
		default:
			return nil, ErrEnvelopedData
		}
		_, recipient.encryptedKey, entry, err = readExpected(entry, 0x04)
		wantLen := 48
		if keyOID.Equal(oidMagmaKExp15) {
			wantLen = 40
		}
		if err != nil || len(entry) != 0 || len(recipient.encryptedKey) != wantLen {
			return nil, ErrEnvelopedData
		}
		recipients = append(recipients, recipient)
	}
	return recipients, nil
}
