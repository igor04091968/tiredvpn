package gostx509

import (
	"bytes"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
)

// ParseRevocationList parses a DER CRL including GOST signature identifiers.
func ParseRevocationList(der []byte) (*RevocationList, error) {
	raw, err := stdx509.ParseRevocationList(der)
	if err != nil {
		return nil, err
	}
	if len(raw.Raw) != len(der) {
		return nil, errors.New("gostx509: trailing CRL data")
	}
	var algorithm pkix.AlgorithmIdentifier
	if rest, err := asn1.Unmarshal(raw.RawSignatureAlgorithm, &algorithm); err != nil || len(rest) != 0 {
		return nil, errors.New("gostx509: malformed CRL signature algorithm")
	}
	if gostAlgorithm := gostSignatureAlgorithm(algorithm.Algorithm); gostAlgorithm != UnknownSignatureAlgorithm {
		raw.SignatureAlgorithm = gostAlgorithm
	}
	return (*RevocationList)(raw), nil
}

// CheckSignatureFrom verifies the CRL with issuer's key. Callers must also
// establish trust in issuer and check the CRL validity interval separately.
func (r *RevocationList) CheckSignatureFrom(issuer *Certificate) error {
	if r == nil || issuer == nil {
		return errors.New("gostx509: missing CRL or issuer")
	}
	if issuer.Version == 3 && !issuer.BasicConstraintsValid || issuer.BasicConstraintsValid && !issuer.IsCA {
		return stdx509.ConstraintViolationError{}
	}
	if issuer.KeyUsage != 0 && issuer.KeyUsage&KeyUsageCRLSign == 0 {
		return stdx509.ConstraintViolationError{}
	}
	if !bytes.Equal(r.RawIssuer, issuer.RawSubject) {
		return errors.New("gostx509: CRL issuer name does not match certificate subject")
	}
	return issuer.CheckSignature(r.SignatureAlgorithm, r.RawTBSRevocationList, r.Signature)
}
