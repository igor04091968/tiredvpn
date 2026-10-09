package gostx509

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
)

// crypto/x509 does not recognize GOST SPKI or signature OIDs. These dummy
// fields are built once; ParseCertificate substitutes them only in a temporary
// copy used to parse the non-cryptographic X.509 fields.
var parserDummy = func() struct{ algorithm, publicKey, signature []byte } {
	mustMarshal := func(value any) []byte {
		der, err := asn1.Marshal(value)
		if err != nil {
			panic(err) // all inputs below are fixed, valid ASN.1 values
		}
		return der
	}
	// Ed25519 has no curve-point conversion or algorithm parameters in the
	// standard parser. The dummy key and signature are never used for crypto.
	algorithm := asn1.ObjectIdentifier{1, 3, 101, 112}
	publicKey := make([]byte, 32)
	signature := make([]byte, 64)
	return struct{ algorithm, publicKey, signature []byte }{
		algorithm: mustMarshal(pkix.AlgorithmIdentifier{Algorithm: algorithm}),
		publicKey: mustMarshal(publicKeyInfoASN1{
			Algorithm: pkix.AlgorithmIdentifier{Algorithm: algorithm},
			PublicKey: asn1.BitString{Bytes: publicKey, BitLength: 8 * len(publicKey)},
		}),
		signature: mustMarshal(asn1.BitString{Bytes: signature, BitLength: 8 * len(signature)}),
	}
}()

func derLengthSize(length int) int {
	if length < 128 {
		return 1
	}
	size := 1
	for length > 0 {
		size++
		length >>= 8
	}
	return size
}

func appendDERHeader(dst []byte, tag byte, length int) []byte {
	dst = append(dst, tag)
	if length < 128 {
		return append(dst, byte(length))
	}
	bytes := derLengthSize(length) - 1
	dst = append(dst, 0x80|byte(bytes))
	for shift := (bytes - 1) * 8; shift >= 0; shift -= 8 {
		dst = append(dst, byte(length>>shift))
	}
	return dst
}

func certificateParserDummyDER(rawTBS []byte) ([]byte, error) {
	const malformed = "gostx509: malformed certificate"
	tag, tbs, trailing, ok := readDERElement(rawTBS)
	if !ok || tag != 0x30 || len(trailing) != 0 {
		return nil, errors.New(malformed)
	}
	sequence := tbs
	if len(sequence) > 0 && sequence[0] == 0xa0 {
		_, _, sequence, ok = readDERElement(sequence)
		if !ok {
			return nil, errors.New(malformed)
		}
	}
	tag, _, sequence, ok = readDERElement(sequence) // serial number
	if !ok || tag != 0x02 {
		return nil, errors.New(malformed)
	}
	prefix := tbs[:len(tbs)-len(sequence)]
	tag, _, sequence, ok = readDERElement(sequence) // original signature algorithm
	if !ok || tag != 0x30 {
		return nil, errors.New(malformed)
	}
	beforeNames := sequence
	for range 3 { // issuer, validity, subject
		tag, _, sequence, ok = readDERElement(sequence)
		if !ok || tag != 0x30 {
			return nil, errors.New(malformed)
		}
	}
	names := beforeNames[:len(beforeNames)-len(sequence)]
	tag, _, suffix, ok := readDERElement(sequence) // original SubjectPublicKeyInfo
	if !ok || tag != 0x30 {
		return nil, errors.New(malformed)
	}

	tbsLength := len(prefix) + len(parserDummy.algorithm) + len(names) + len(parserDummy.publicKey) + len(suffix)
	tbsDERLength := 1 + derLengthSize(tbsLength) + tbsLength
	outerLength := tbsDERLength + len(parserDummy.algorithm) + len(parserDummy.signature)
	der := make([]byte, 0, 1+derLengthSize(outerLength)+outerLength)
	der = appendDERHeader(der, 0x30, outerLength)
	der = appendDERHeader(der, 0x30, tbsLength)
	der = append(der, prefix...)
	der = append(der, parserDummy.algorithm...)
	der = append(der, names...)
	der = append(der, parserDummy.publicKey...)
	der = append(der, suffix...)
	der = append(der, parserDummy.algorithm...)
	der = append(der, parserDummy.signature...)
	return der, nil
}
