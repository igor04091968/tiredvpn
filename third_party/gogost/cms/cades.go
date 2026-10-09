package cms

import (
	"errors"
)

// AddSignatureTimeStamp attaches an RFC 5126 CAdES-T unsigned attribute to
// signerIndex. The token must stamp exactly that signer's signature. It checks
// the token's CMS signature, but the caller must validate TSA trust separately.
// Re-encoding an attached signature copies its embedded content.
func AddSignatureTimeStamp(signedDER []byte, signerIndex int, tokenDER []byte) ([]byte, error) {
	signed, err := ParseSignedData(signedDER)
	if err != nil || signerIndex < 0 || signerIndex >= len(signed.Signers) {
		return nil, ErrSignedData
	}
	token, err := ParseTimeStampToken(tokenDER)
	if err != nil {
		return nil, err
	}
	if err = token.VerifyImprint(signed.Signers[signerIndex].Signature); err != nil {
		return nil, err
	}
	if err = token.ValidateTSASigner(); err != nil {
		return nil, err
	}
	results, err := token.VerifySignatures()
	if err != nil || len(results) != 1 || results[0].Err != nil {
		return nil, ErrTimeStamp
	}
	_, outer, tail, err := readExpectedBER(signedDER, 0x30)
	if err != nil || len(tail) != 0 {
		return nil, ErrSignedData
	}
	oidFull, _, outer, err := readExpected(outer, 0x06)
	if err != nil {
		return nil, ErrSignedData
	}
	_, explicit, tail, err := readExpectedBER(outer, 0xa0)
	if err != nil || len(tail) != 0 {
		return nil, ErrSignedData
	}
	_, body, tail, err := readExpectedBER(explicit, 0x30)
	if err != nil || len(tail) != 0 {
		return nil, ErrSignedData
	}
	rest := body
	for i := 0; i < 3; i++ { // version, digestAlgorithms, encapContentInfo
		_, _, _, rest, err = readBER(rest, 0)
		if err != nil {
			return nil, ErrSignedData
		}
	}
	for len(rest) != 0 && (rest[0] == 0xa0 || rest[0] == 0xa1) {
		_, _, _, rest, err = readBER(rest, 0)
		if err != nil {
			return nil, ErrSignedData
		}
	}
	_, infos, tail, err := readExpectedBER(rest, 0x31)
	if err != nil || len(tail) != 0 {
		return nil, ErrSignedData
	}
	items := make([][]byte, 0, len(signed.Signers))
	for len(infos) != 0 {
		full, _, next, e := readExpectedBER(infos, 0x30)
		if e != nil {
			return nil, ErrSignedData
		}
		items = append(items, full)
		infos = next
	}
	items[signerIndex], err = addStampToSigner(items[signerIndex], tokenDER)
	if err != nil {
		return nil, err
	}
	updated := derWrap(0x30, body[:len(body)-len(rest)], derSet(items...))
	return derWrap(0x30, oidFull, derWrap(0xa0, updated)), nil
}

func addStampToSigner(encoded, token []byte) ([]byte, error) {
	_, body, tail, err := readExpected(encoded, 0x30)
	if err != nil || len(tail) != 0 {
		return nil, ErrSignedData
	}
	rest := body
	for i := 0; i < 3; i++ { // version, sid, digestAlgorithm
		_, _, _, rest, err = readDER(rest)
		if err != nil {
			return nil, ErrSignedData
		}
	}
	if len(rest) != 0 && rest[0] == 0xa0 {
		_, _, _, rest, err = readDER(rest)
		if err != nil {
			return nil, ErrSignedData
		}
	}
	for i := 0; i < 2; i++ { // signatureAlgorithm, signature
		_, _, _, rest, err = readDER(rest)
		if err != nil {
			return nil, ErrSignedData
		}
	}
	prefix := body[:len(body)-len(rest)]
	attrs := make([][]byte, 0, 4)
	stamped := false
	if len(rest) != 0 {
		_, old, tail, e := readExpected(rest, 0xa1)
		if e != nil || len(tail) != 0 {
			return nil, ErrSignedData
		}
		for len(old) != 0 {
			full, attrBody, next, e := readExpected(old, 0x30)
			if e != nil || len(attrs) >= 32 {
				return nil, ErrSignedData
			}
			oid, attrBody, e := parseOID(attrBody)
			if e != nil {
				return nil, ErrSignedData
			}
			if oid.Equal(oidSignatureTimeStamp) {
				if stamped {
					return nil, ErrSignedData
				}
				stamped = true
				_, values, trailing, e := readExpected(attrBody, 0x31)
				if e != nil || len(trailing) != 0 {
					return nil, ErrSignedData
				}
				items := [][]byte{token}
				for len(values) != 0 {
					v, _, nextValue, e := readExpected(values, 0x30)
					if e != nil || len(items) >= 16 {
						return nil, ErrSignedData
					}
					items = append(items, v)
					values = nextValue
				}
				full = derWrap(0x30, derOID(oidSignatureTimeStamp), derSet(items...))
			}
			attrs = append(attrs, full)
			old = next
		}
	}
	if !stamped {
		attrs = append(attrs, makeAttribute(oidSignatureTimeStamp, token))
	}
	_, attrBody, _, err := readExpected(derSet(attrs...), 0x31)
	if err != nil {
		return nil, ErrSignedData
	}
	return derWrap(0x30, prefix, derWrap(0xa1, attrBody)), nil
}

// VerifySignatureTimeStamps validates the signature-time-stamp token's imprint
// and CMS signature for each signer. It does not establish TSA trust.
func (s *SignedData) VerifySignatureTimeStamps() [][]error {
	if s == nil {
		return nil
	}
	out := make([][]error, len(s.Signers))
	for i := range s.Signers {
		info := &s.Signers[i]
		out[i] = make([]error, len(info.SignatureTimeStamps))
		for j, token := range info.SignatureTimeStamps {
			if err := token.VerifyImprint(info.Signature); err != nil {
				out[i][j] = err
				continue
			}
			if err := token.ValidateTSASigner(); err != nil {
				out[i][j] = err
				continue
			}
			results, err := token.VerifySignatures()
			if err != nil || len(results) != 1 || results[0].Err != nil {
				out[i][j] = errors.New("gogost/cms: Некорректная метка времени подписи")
			}
		}
	}
	return out
}
