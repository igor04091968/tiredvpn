package gostx509

import (
	"bytes"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"

	"gitverse.ru/uzer_007/gogost/v3/gost3410"
	"gitverse.ru/uzer_007/gogost/v3/gost34112012512"
)

var (
	oidPFXData           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidPFXEncryptedData  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	oidPFXShroudedKeyBag = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	oidPFXCertBag        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidPFXX509Cert       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
	oidPFXLocalKeyID     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 21}
	oidStreebog512       = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 3}
)

type pfxContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue
}

type pfxMacData struct {
	Mac struct {
		DigestAlgorithm pkix.AlgorithmIdentifier
		Digest          []byte
	}
	Salt       []byte
	Iterations int
}

type pfxASN1 struct {
	Version  int
	AuthSafe pfxContentInfo
	MacData  pfxMacData
}

type pfxSafeBag struct {
	BagID         asn1.ObjectIdentifier
	BagValue      asn1.RawValue
	BagAttributes asn1.RawValue `asn1:"optional"`
}

type pfxCertBagASN1 struct {
	CertID    asn1.ObjectIdentifier
	CertValue asn1.RawValue
}

type pfxEncryptedDataASN1 struct {
	Version              int
	EncryptedContentInfo struct {
		ContentType                asn1.ObjectIdentifier
		ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
		EncryptedContent           asn1.RawValue `asn1:"optional,tag:0"`
	}
}

type pfxAttribute struct {
	ID     asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

func pfxExplicit(der []byte) asn1.RawValue {
	return asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: der}
}

func pfxDataContent(data []byte) (pfxContentInfo, error) {
	octets, err := asn1.Marshal(data)
	if err != nil {
		return pfxContentInfo{}, err
	}
	return pfxContentInfo{ContentType: oidPFXData, Content: pfxExplicit(octets)}, nil
}

func pfxLocalKeyID(id []byte) (asn1.RawValue, error) {
	value, err := asn1.Marshal(id)
	if err != nil {
		return asn1.RawValue{}, err
	}
	attr, err := asn1.Marshal(pfxAttribute{ID: oidPFXLocalKeyID, Values: []asn1.RawValue{{FullBytes: value}}})
	if err != nil {
		return asn1.RawValue{}, err
	}
	attrs, err := asn1.Marshal([]asn1.RawValue{{FullBytes: attr}})
	if err != nil {
		return asn1.RawValue{}, err
	}
	attrs[0] = 0x31 // SET OF Attribute
	return asn1.RawValue{FullBytes: attrs}, nil
}

func pfxMac(password string, salt, data []byte, iterations int) ([]byte, error) {
	derived, err := pbkdf2.Key(gost34112012512.New, password, salt, iterations, 96)
	if err != nil {
		return nil, err
	}
	defer clear(derived)
	mac := hmac.New(gost34112012512.New, derived[64:])
	_, _ = mac.Write(data)
	return mac.Sum(nil), nil
}

// MarshalPFX creates an RFC 9548 password-protected PFX. The certificate
// is matched to the private key before encoding, and the authenticated safe
// is protected by a separately salted HMAC-Streebog-512.
func MarshalPFX(key any, certificate *Certificate, chain []*Certificate, password string) ([]byte, error) {
	return MarshalPFXWithOptions(key, certificate, chain, password, nil)
}

// MarshalPFXWithOptions chooses the encrypted private-key profile inside an
// integrity-protected PFX. Legacy28147 can be used for older recipients.
func MarshalPFXWithOptions(key any, certificate *Certificate, chain []*Certificate, password string, options *EncryptedPKCS8Options) ([]byte, error) {
	if certificate == nil || len(certificate.Raw) == 0 {
		return nil, errors.New("gostx509: missing PFX certificate")
	}
	if err := matchPFXKeyCertificate(key, certificate); err != nil {
		return nil, err
	}
	keyDER, err := MarshalEncryptedPKCS8PrivateKey(key, password, options)
	if err != nil {
		return nil, err
	}
	defer clear(keyDER)
	keyID := sha1.Sum(certificate.RawSubjectPublicKeyInfo)
	attr, err := pfxLocalKeyID(keyID[:])
	if err != nil {
		return nil, err
	}
	keyBagDER, err := asn1.Marshal(pfxSafeBag{BagID: oidPFXShroudedKeyBag, BagValue: pfxExplicit(keyDER), BagAttributes: attr})
	if err != nil {
		return nil, err
	}
	keySafe, err := asn1.Marshal([]asn1.RawValue{{FullBytes: keyBagDER}})
	if err != nil {
		return nil, err
	}
	keyInfo, err := pfxDataContent(keySafe)
	if err != nil {
		return nil, err
	}
	certs := append([]*Certificate{certificate}, chain...)
	if len(certs) > 32 {
		return nil, errors.New("gostx509: too many PFX certificates")
	}
	var certBags []asn1.RawValue
	for i, cert := range certs {
		if cert == nil || len(cert.Raw) == 0 {
			return nil, errors.New("gostx509: missing PFX chain certificate")
		}
		value, err := asn1.Marshal(cert.Raw)
		if err != nil {
			return nil, err
		}
		certBag, err := asn1.Marshal(pfxCertBagASN1{CertID: oidPFXX509Cert, CertValue: pfxExplicit(value)})
		if err != nil {
			return nil, err
		}
		bag := pfxSafeBag{BagID: oidPFXCertBag, BagValue: pfxExplicit(certBag)}
		if i == 0 {
			bag.BagAttributes = attr
		}
		der, err := asn1.Marshal(bag)
		if err != nil {
			return nil, err
		}
		certBags = append(certBags, asn1.RawValue{FullBytes: der})
	}
	certSafe, err := asn1.Marshal(certBags)
	if err != nil {
		return nil, err
	}
	certInfo, err := pfxDataContent(certSafe)
	if err != nil {
		return nil, err
	}
	authSafe, err := asn1.Marshal([]pfxContentInfo{certInfo, keyInfo})
	if err != nil {
		return nil, err
	}
	authInfo, err := pfxDataContent(authSafe)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	mac, err := pfxMac(password, salt, authSafe, defaultPKCS8Iterations)
	if err != nil {
		return nil, err
	}
	var out pfxASN1
	out.Version = 3
	out.AuthSafe = authInfo
	out.MacData.Mac.DigestAlgorithm = pkix.AlgorithmIdentifier{Algorithm: oidStreebog512}
	out.MacData.Mac.Digest = mac
	out.MacData.Salt = salt
	out.MacData.Iterations = defaultPKCS8Iterations
	return asn1.Marshal(out)
}

// ParsePFX verifies the RFC 9548 MAC, decrypts the key, then checks the
// key/certificate pair. Certificate chain trust is left to the caller.
func ParsePFX(der []byte, password string) (any, *Certificate, []*Certificate, error) {
	if len(der) > maxEncryptedPKCS8Size {
		return nil, nil, nil, errors.New("gostx509: PFX too large")
	}
	var container pfxASN1
	rest, err := asn1.Unmarshal(der, &container)
	if err != nil || len(rest) != 0 || container.Version != 3 {
		return nil, nil, nil, errors.New("gostx509: malformed PFX")
	}
	if !container.AuthSafe.ContentType.Equal(oidPFXData) || container.AuthSafe.Content.Class != 2 || container.AuthSafe.Content.Tag != 0 || !container.MacData.Mac.DigestAlgorithm.Algorithm.Equal(oidStreebog512) || len(container.MacData.Mac.DigestAlgorithm.Parameters.FullBytes) != 0 {
		return nil, nil, nil, errors.New("gostx509: unsupported PFX integrity profile")
	}
	if len(container.MacData.Salt) < 8 || len(container.MacData.Salt) > 32 || container.MacData.Iterations < 1000 || container.MacData.Iterations > maxPKCS8Iterations || len(container.MacData.Mac.Digest) != 64 {
		return nil, nil, nil, errors.New("gostx509: invalid PFX MAC parameters")
	}
	var authSafe []byte
	rest, err = asn1.Unmarshal(container.AuthSafe.Content.Bytes, &authSafe)
	if err != nil || len(rest) != 0 {
		return nil, nil, nil, errors.New("gostx509: malformed PFX authenticated safe")
	}
	computed, err := pfxMac(password, container.MacData.Salt, authSafe, container.MacData.Iterations)
	if err != nil {
		return nil, nil, nil, err
	}
	if !hmac.Equal(computed, container.MacData.Mac.Digest) {
		return nil, nil, nil, errors.New("gostx509: wrong PFX password or MAC")
	}
	var contents []pfxContentInfo
	rest, err = asn1.Unmarshal(authSafe, &contents)
	if err != nil || len(rest) != 0 || len(contents) == 0 || len(contents) > 32 {
		return nil, nil, nil, errors.New("gostx509: malformed PFX contents")
	}
	var key any
	var keyID []byte
	var certs []*Certificate
	var certIDs [][]byte
	for _, content := range contents {
		var safe []byte
		if content.Content.Class != 2 || content.Content.Tag != 0 {
			return nil, nil, nil, errors.New("gostx509: malformed PFX content")
		}
		switch {
		case content.ContentType.Equal(oidPFXData):
			rest, err = asn1.Unmarshal(content.Content.Bytes, &safe)
			if err != nil || len(rest) != 0 {
				return nil, nil, nil, errors.New("gostx509: malformed PFX data")
			}
		case content.ContentType.Equal(oidPFXEncryptedData):
			var encrypted pfxEncryptedDataASN1
			rest, err = asn1.Unmarshal(content.Content.Bytes, &encrypted)
			if err != nil || len(rest) != 0 || encrypted.Version != 0 || !encrypted.EncryptedContentInfo.ContentType.Equal(oidPFXData) || encrypted.EncryptedContentInfo.EncryptedContent.Class != 2 || encrypted.EncryptedContentInfo.EncryptedContent.Tag != 0 {
				return nil, nil, nil, errors.New("gostx509: malformed PFX EncryptedData")
			}
			safe, err = decryptPBES2(encrypted.EncryptedContentInfo.ContentEncryptionAlgorithm, encrypted.EncryptedContentInfo.EncryptedContent.Bytes, password)
			if err != nil {
				return nil, nil, nil, err
			}
		default:
			return nil, nil, nil, errors.New("gostx509: unsupported PFX content type")
		}
		var bags []pfxSafeBag
		rest, err = asn1.Unmarshal(safe, &bags)
		if err != nil || len(rest) != 0 || len(bags) > 64 {
			return nil, nil, nil, errors.New("gostx509: malformed PFX safe bags")
		}
		for _, bag := range bags {
			if bag.BagValue.Class != 2 || bag.BagValue.Tag != 0 {
				return nil, nil, nil, errors.New("gostx509: malformed PFX bag value")
			}
			id, err := parsePFXLocalKeyID(bag.BagAttributes)
			if err != nil {
				return nil, nil, nil, err
			}
			switch {
			case bag.BagID.Equal(oidPFXShroudedKeyBag):
				if key != nil {
					return nil, nil, nil, errors.New("gostx509: multiple PFX private keys")
				}
				key, err = ParseEncryptedPKCS8PrivateKey(bag.BagValue.Bytes, password)
				if err != nil {
					return nil, nil, nil, err
				}
				keyID = id
			case bag.BagID.Equal(oidPFXCertBag):
				var certBag pfxCertBagASN1
				rest, err = asn1.Unmarshal(bag.BagValue.Bytes, &certBag)
				if err != nil || len(rest) != 0 || !certBag.CertID.Equal(oidPFXX509Cert) || certBag.CertValue.Class != 2 || certBag.CertValue.Tag != 0 {
					return nil, nil, nil, errors.New("gostx509: unsupported PFX certificate bag")
				}
				var certDER []byte
				rest, err = asn1.Unmarshal(certBag.CertValue.Bytes, &certDER)
				if err != nil || len(rest) != 0 {
					return nil, nil, nil, errors.New("gostx509: malformed PFX certificate")
				}
				cert, err := ParseCertificate(certDER)
				if err != nil {
					return nil, nil, nil, err
				}
				certs = append(certs, cert)
				certIDs = append(certIDs, id)
			default:
				return nil, nil, nil, fmt.Errorf("gostx509: unsupported PFX bag %v", bag.BagID)
			}
		}
	}
	if key == nil || len(certs) == 0 {
		return nil, nil, nil, errors.New("gostx509: PFX key or certificate missing")
	}
	match := -1
	for i, cert := range certs {
		if len(keyID) > 0 && len(certIDs[i]) > 0 && !bytes.Equal(keyID, certIDs[i]) {
			continue
		}
		if matchPFXKeyCertificate(key, cert) == nil {
			if match >= 0 {
				return nil, nil, nil, errors.New("gostx509: ambiguous PFX key binding")
			}
			match = i
		}
	}
	if match < 0 {
		return nil, nil, nil, errors.New("gostx509: PFX key does not match any certificate")
	}
	leaf := certs[match]
	chain := append(append([]*Certificate(nil), certs[:match]...), certs[match+1:]...)
	return key, leaf, chain, nil
}

func parsePFXLocalKeyID(raw asn1.RawValue) ([]byte, error) {
	if len(raw.FullBytes) == 0 {
		return nil, nil
	}
	if raw.Tag != asn1.TagSet || raw.Class != 0 {
		return nil, errors.New("gostx509: malformed PFX attributes")
	}
	for data := raw.Bytes; len(data) > 0; {
		var attr pfxAttribute
		rest, err := asn1.Unmarshal(data, &attr)
		if err != nil {
			return nil, errors.New("gostx509: malformed PFX attribute")
		}
		if attr.ID.Equal(oidPFXLocalKeyID) {
			if len(attr.Values) != 1 {
				return nil, errors.New("gostx509: malformed PFX localKeyID")
			}
			var id []byte
			if extra, err := asn1.Unmarshal(attr.Values[0].FullBytes, &id); err != nil || len(extra) != 0 {
				return nil, errors.New("gostx509: malformed PFX localKeyID")
			}
			return id, nil
		}
		data = rest
	}
	return nil, nil
}

func matchPFXKeyCertificate(key any, certificate *Certificate) error {
	if certificate == nil {
		return errors.New("gostx509: missing certificate")
	}
	pub, ok := gostPublicKey(key)
	if !ok {
		return errors.New("gostx509: PFX currently requires a GOST private key")
	}
	certPub, ok := certificate.PublicKey.(*gost3410.PublicKey)
	if !ok || !pub.Equal(certPub) {
		return errors.New("gostx509: PFX private key and certificate do not match")
	}
	return nil
}
