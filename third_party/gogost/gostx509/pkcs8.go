package gostx509

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"gitverse.ru/uzer_007/gogost/v3/gost3410"
)

type pkcs8 struct {
	Version    int
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey []byte
	Attributes []asn1.RawValue `asn1:"optional,tag:0"`
	PublicKey  asn1.BitString  `asn1:"optional,tag:1"`
}

// ParsePKCS8PrivateKey parses a PKCS #8 private key, including GOST R
// 34.10-2012 keys.
func ParsePKCS8PrivateKey(der []byte) (any, error) {
	if key, err := stdx509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	var info pkcs8
	rest, err := asn1.Unmarshal(der, &info)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("gostx509: malformed PKCS #8 private key")
	}
	if !isGOSTPublicKeyOID(info.Algorithm.Algorithm) {
		return nil, fmt.Errorf("gostx509: unsupported PKCS #8 algorithm %v", info.Algorithm.Algorithm)
	}
	var params GostR341012PublicKeyParameters
	rest, err = asn1.Unmarshal(info.Algorithm.Parameters.FullBytes, &params)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("gostx509: malformed GOST PKCS #8 parameters")
	}
	curve, err := curveForOID(params.PublicKeyParamSet)
	if err != nil {
		return nil, err
	}
	if err := validateGOSTAlgorithmCurve(info.Algorithm.Algorithm, curve); err != nil {
		return nil, err
	}
	if info.Version != 0 && info.Version != 1 {
		return nil, errors.New("gostx509: unsupported PKCS #8 version")
	}
	var raw []byte
	value := info.PrivateKey
	if info.Version == 0 {
		// Older GOST PKCS #8 producers use a nested OCTET STRING or a
		// KeyValueInfo SEQUENCE; R 50.1.112 also permits raw mask bytes.
		if len(value)%curve.PointSize() != 0 {
			if len(value) > 0 && value[0] == 0x30 {
				var keyValue struct{ KeyValueMask, PublicKey []byte }
				if rest, err = asn1.Unmarshal(value, &keyValue); err != nil || len(rest) != 0 {
					return nil, errors.New("gostx509: malformed GOST PKCS #8 key value")
				}
				value = keyValue.KeyValueMask
			} else if len(value) > 0 && value[0] == 0x04 {
				if rest, err = asn1.Unmarshal(value, &raw); err != nil || len(rest) != 0 {
					return nil, errors.New("gostx509: malformed GOST PKCS #8 key value")
				}
				value = raw
			} else {
				return nil, errors.New("gostx509: malformed GOST PKCS #8 key value")
			}
		}
	}
	// RFC 9548 and R 50.1.112 store little-endian scalar factors, with
	// optional multiplicative masks following the first factor.
	pointSize := curve.PointSize()
	if len(value) == 0 || len(value)%pointSize != 0 || len(value) > 16*pointSize {
		return nil, errors.New("gostx509: malformed masked GOST PKCS #8 key")
	}
	scalar := new(big.Int)
	for offset := 0; offset < len(value); offset += pointSize {
		chunk := append([]byte(nil), value[offset:offset+pointSize]...)
		for i, j := 0, len(chunk)-1; i < j; i, j = i+1, j-1 {
			chunk[i], chunk[j] = chunk[j], chunk[i]
		}
		factor := new(big.Int).SetBytes(chunk)
		clear(chunk)
		if factor.Sign() == 0 || factor.Cmp(curve.Q) >= 0 {
			return nil, errors.New("gostx509: invalid GOST PKCS #8 key mask")
		}
		if offset == 0 {
			scalar.Set(factor)
		} else {
			scalar.Mul(scalar, factor).Mod(scalar, curve.Q)
		}
	}
	raw = make([]byte, pointSize)
	scalar.FillBytes(raw)
	for i, j := 0, len(raw)-1; i < j; i, j = i+1, j-1 {
		raw[i], raw[j] = raw[j], raw[i]
	}
	private, err := gost3410.NewPrivateKey(curve, raw)
	if err != nil {
		return nil, err
	}
	if private.Key.Sign() == 0 {
		return nil, errors.New("gostx509: invalid zero GOST private key")
	}
	if len(info.PublicKey.Bytes) != 0 {
		pub, err := private.PublicKey()
		if err != nil {
			return nil, err
		}
		embedded := info.PublicKey.Bytes
		if !bytes.Equal(embedded, pub.Raw()) {
			var wrapped []byte
			if rest, err := asn1.Unmarshal(embedded, &wrapped); err != nil || len(rest) != 0 || !bytes.Equal(wrapped, pub.Raw()) {
				return nil, errors.New("gostx509: PKCS #8 public key does not match private key")
			}
		}
	}
	return private, nil
}

// MarshalPKCS8PrivateKey marshals a private key as PKCS #8.
func MarshalPKCS8PrivateKey(key any) ([]byte, error) {
	var private *gost3410.PrivateKey
	switch k := key.(type) {
	case *gost3410.PrivateKey:
		private = k
	case *gost3410.PrivateKeyReverseDigest:
		private = k.Prv
	case *gost3410.PrivateKeyReverseDigestAndSignature:
		private = k.Prv
	default:
		return stdx509.MarshalPKCS8PrivateKey(key)
	}
	public, err := private.PublicKey()
	if err != nil {
		return nil, err
	}
	algorithm, err := gostAlgorithmIdentifier(public)
	if err != nil {
		return nil, err
	}
	publicDER, err := asn1.Marshal(public.Raw())
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(pkcs8{
		Version:    1,
		Algorithm:  algorithm,
		PrivateKey: private.Raw(),
		PublicKey:  asn1.BitString{Bytes: publicDER, BitLength: 8 * len(publicDER)},
	})
}

func ParsePKCS1PrivateKey(der []byte) (*rsa.PrivateKey, error) {
	return stdx509.ParsePKCS1PrivateKey(der)
}

func MarshalPKCS1PrivateKey(key *rsa.PrivateKey) []byte {
	return stdx509.MarshalPKCS1PrivateKey(key)
}

func ParsePKCS1PublicKey(der []byte) (*rsa.PublicKey, error) {
	return stdx509.ParsePKCS1PublicKey(der)
}

func MarshalPKCS1PublicKey(key *rsa.PublicKey) []byte {
	return stdx509.MarshalPKCS1PublicKey(key)
}

func ParseECPrivateKey(der []byte) (*ecdsa.PrivateKey, error) {
	return stdx509.ParseECPrivateKey(der)
}

func MarshalECPrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	return stdx509.MarshalECPrivateKey(key)
}
