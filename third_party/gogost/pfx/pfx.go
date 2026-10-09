// Package pfx handles GOST PKCS #12 transport containers. Password protection
// follows RFC 9548; public-key protection follows R 1323565.1.041-2022.
package pfx

import (
	"crypto"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"gitverse.ru/uzer_007/gogost/v3/cms"
	"gitverse.ru/uzer_007/gogost/v3/gost3410"
	"gitverse.ru/uzer_007/gogost/v3/gostx509"
	"gitverse.ru/uzer_007/gogost/v3/keywrap"
)

const maxPFXSize = 16 << 20

var (
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidKeyBag        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 1}
	oidCertBag       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidX509Cert      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
	ErrPFX           = errors.New("gogost/pfx: invalid public-key-protected PFX")
)

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue
}

type safeBag struct {
	BagID         asn1.ObjectIdentifier
	BagValue      asn1.RawValue
	BagAttributes asn1.RawValue `asn1:"optional"`
}

type certBag struct {
	CertID    asn1.ObjectIdentifier
	CertValue asn1.RawValue
}

type outerPFX struct {
	Version  int
	AuthSafe asn1.RawValue
	MacData  asn1.RawValue `asn1:"optional"`
}

// PublicKeyContainer contains the transported key and certificates. Signatures
// are checked mathematically during parsing; the caller must independently
// establish trust in Signers and the transported certificate chain.
type PublicKeyContainer struct {
	Key         *gost3410.PrivateKey
	Certificate *gostx509.Certificate
	Chain       []*gostx509.Certificate
	Signers     []*gostx509.Certificate
}

// RecipientProtection selects the authorized decryptors and the signer of the
// AuthenticatedSafe. Algorithm selects Kuznechik or Magma KExp15/CTR-ACPKM,
// or CryptoPro for the GOST 28147-89 legacy transport profile.
type RecipientProtection struct {
	Recipients        []*gostx509.Certificate
	SignerCertificate *gostx509.Certificate
	Signer            crypto.Signer
	Algorithm         keywrap.Algorithm
	LegacyParamSet    cms.LegacyParamSet // Used only with AlgorithmCryptoPro; zero selects CryptoPro-A.
}

// MarshalPassword uses the RFC 9548 password-protected profile.
func MarshalPassword(key any, certificate *gostx509.Certificate, chain []*gostx509.Certificate, password string) ([]byte, error) {
	return gostx509.MarshalPFX(key, certificate, chain, password)
}

// MarshalPasswordWithOptions selects the encrypted private-key profile within
// the MAC-protected PFX. The default is authenticated Kuznechik.
func MarshalPasswordWithOptions(key any, certificate *gostx509.Certificate, chain []*gostx509.Certificate, password string, options *gostx509.EncryptedPKCS8Options) ([]byte, error) {
	return gostx509.MarshalPFXWithOptions(key, certificate, chain, password, options)
}

// ParsePassword verifies the outer MAC before decoding the key and bags.
func ParsePassword(der []byte, password string) (any, *gostx509.Certificate, []*gostx509.Certificate, error) {
	return gostx509.ParsePFX(der, password)
}

// MarshalForRecipients protects the private-key bag for every recipient using
// GOST CMS EnvelopedData, then signs the complete AuthenticatedSafe.
// The sender certificate is included for mathematical signature verification;
// its trust is outside this package. A fresh random mask protects the encoded
// GOST private scalar even within the CMS ciphertext.
func MarshalForRecipients(key *gost3410.PrivateKey, certificate *gostx509.Certificate, chain []*gostx509.Certificate, protection RecipientProtection) ([]byte, error) {
	if key == nil || certificate == nil || protection.SignerCertificate == nil || protection.Signer == nil || len(protection.Recipients) == 0 || len(protection.Recipients) > 32 || len(chain) > 32 {
		return nil, ErrPFX
	}
	if err := matchKeyCertificate(key, certificate); err != nil {
		return nil, err
	}
	keyDER, err := marshalMaskedKey(key)
	if err != nil {
		return nil, err
	}
	defer clear(keyDER)
	keyBagDER, err := asn1.Marshal(safeBag{BagID: oidKeyBag, BagValue: explicit(keyDER)})
	if err != nil {
		return nil, err
	}
	defer clear(keyBagDER)
	keySafe, err := asn1.Marshal([]asn1.RawValue{{FullBytes: keyBagDER}})
	if err != nil {
		return nil, err
	}
	defer clear(keySafe)
	var enveloped []byte
	if protection.Algorithm == keywrap.AlgorithmCryptoPro {
		enveloped, err = cms.EncryptEnvelopedLegacyWithParamSet(keySafe, protection.Recipients, protection.LegacyParamSet)
	} else {
		if protection.LegacyParamSet != 0 {
			return nil, ErrPFX
		}
		enveloped, err = cms.EncryptEnveloped2012(keySafe, protection.Recipients, protection.Algorithm)
	}
	if err != nil {
		return nil, err
	}
	certBags := make([]asn1.RawValue, 0, len(chain)+1)
	for _, cert := range append([]*gostx509.Certificate{certificate}, chain...) {
		if cert == nil || len(cert.Raw) == 0 {
			return nil, ErrPFX
		}
		value, err := asn1.Marshal(cert.Raw)
		if err != nil {
			return nil, err
		}
		bagDER, err := asn1.Marshal(certBag{CertID: oidX509Cert, CertValue: explicit(value)})
		if err != nil {
			return nil, err
		}
		safeDER, err := asn1.Marshal(safeBag{BagID: oidCertBag, BagValue: explicit(bagDER)})
		if err != nil {
			return nil, err
		}
		certBags = append(certBags, asn1.RawValue{FullBytes: safeDER})
	}
	certSafe, err := asn1.Marshal(certBags)
	if err != nil {
		return nil, err
	}
	certOctets, err := asn1.Marshal(certSafe)
	if err != nil {
		return nil, err
	}
	dataInfo, err := asn1.Marshal(contentInfo{ContentType: oidData, Content: explicit(certOctets)})
	if err != nil {
		return nil, err
	}
	authSafe, err := asn1.Marshal([]asn1.RawValue{{FullBytes: enveloped}, {FullBytes: dataInfo}})
	if err != nil {
		return nil, err
	}
	if len(authSafe) > maxPFXSize/2 {
		return nil, ErrPFX
	}
	signed, err := cms.SignAttached(authSafe, protection.SignerCertificate, protection.Signer)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(struct {
		Version  int
		AuthSafe asn1.RawValue
	}{3, asn1.RawValue{FullBytes: signed}})
}

// ParseForRecipient verifies the sender's CMS signature before decrypting any
// section. It rejects unsupported bags and ambiguous key/certificate binding.
// Returned certificates may reference der; keep it alive and unchanged.
func ParseForRecipient(der []byte, recipientCert *gostx509.Certificate, recipientKey *gost3410.PrivateKey) (*PublicKeyContainer, error) {
	if len(der) == 0 || len(der) > maxPFXSize || recipientCert == nil || recipientKey == nil {
		return nil, ErrPFX
	}
	var outer outerPFX
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil || len(rest) != 0 || outer.Version != 3 || len(outer.MacData.FullBytes) != 0 {
		return nil, ErrPFX
	}
	var signedInfo contentInfo
	if rest, err = asn1.Unmarshal(outer.AuthSafe.FullBytes, &signedInfo); err != nil || len(rest) != 0 || !signedInfo.ContentType.Equal(oidSignedData) {
		return nil, ErrPFX
	}
	signed, err := cms.ParseSignedData(outer.AuthSafe.FullBytes)
	if err != nil || signed.Detached || len(signed.Signers) == 0 {
		return nil, ErrPFX
	}
	results, err := signed.Verify(nil)
	if err != nil || len(results) != len(signed.Signers) {
		return nil, ErrPFX
	}
	out := &PublicKeyContainer{}
	for _, result := range results {
		if result.Err != nil || result.Signer == nil || result.Signer.Certificate == nil {
			return nil, ErrPFX
		}
		out.Signers = append(out.Signers, result.Signer.Certificate)
	}
	if len(signed.Content) > maxPFXSize/2 {
		return nil, ErrPFX
	}
	var sections []asn1.RawValue
	if rest, err = asn1.Unmarshal(signed.Content, &sections); err != nil || len(rest) != 0 || len(sections) == 0 || len(sections) > 32 {
		return nil, ErrPFX
	}
	var certs []*gostx509.Certificate
	for _, section := range sections {
		var info contentInfo
		if rest, err = asn1.Unmarshal(section.FullBytes, &info); err != nil || len(rest) != 0 || info.Content.Class != 2 || info.Content.Tag != 0 {
			return nil, ErrPFX
		}
		var safe []byte
		switch {
		case info.ContentType.Equal(oidData):
			if rest, err = asn1.Unmarshal(info.Content.Bytes, &safe); err != nil || len(rest) != 0 {
				return nil, ErrPFX
			}
		case info.ContentType.Equal(oidEnvelopedData):
			envelope, err := cms.ParseEnvelopedData(section.FullBytes)
			if err != nil {
				return nil, fmt.Errorf("%w: parse EnvelopedData: %v", ErrPFX, err)
			}
			safe, err = envelope.DecryptUnauthenticated(recipientCert, recipientKey)
			if err != nil {
				return nil, fmt.Errorf("%w: decrypt EnvelopedData: %v", ErrPFX, err)
			}
			defer clear(safe)
		default:
			return nil, fmt.Errorf("%w: unsupported content type %v", ErrPFX, info.ContentType)
		}
		var bags []safeBag
		if rest, err = asn1.Unmarshal(safe, &bags); err != nil || len(rest) != 0 || len(bags) > 64 {
			return nil, ErrPFX
		}
		for _, bag := range bags {
			if bag.BagValue.Class != 2 || bag.BagValue.Tag != 0 {
				return nil, ErrPFX
			}
			switch {
			case bag.BagID.Equal(oidKeyBag):
				if out.Key != nil {
					return nil, ErrPFX
				}
				parsed, err := gostx509.ParsePKCS8PrivateKey(bag.BagValue.Bytes)
				if err != nil {
					return nil, err
				}
				var ok bool
				out.Key, ok = parsed.(*gost3410.PrivateKey)
				if !ok {
					return nil, ErrPFX
				}
			case bag.BagID.Equal(oidCertBag):
				var encoded certBag
				if rest, err = asn1.Unmarshal(bag.BagValue.Bytes, &encoded); err != nil || len(rest) != 0 || !encoded.CertID.Equal(oidX509Cert) || encoded.CertValue.Class != 2 || encoded.CertValue.Tag != 0 {
					return nil, ErrPFX
				}
				var certDER []byte
				if rest, err = asn1.Unmarshal(encoded.CertValue.Bytes, &certDER); err != nil || len(rest) != 0 {
					return nil, ErrPFX
				}
				// The decrypted SafeContents is cleared below; keep returned
				// certificates independent of that buffer.
				cert, err := gostx509.ParseCertificate(append([]byte(nil), certDER...))
				if err != nil {
					return nil, err
				}
				certs = append(certs, cert)
			default:
				return nil, fmt.Errorf("%w: unsupported bag %v", ErrPFX, bag.BagID)
			}
		}
	}
	if out.Key == nil || len(certs) == 0 || len(certs) > 32 {
		return nil, ErrPFX
	}
	for _, cert := range certs {
		if matchKeyCertificate(out.Key, cert) == nil {
			if out.Certificate != nil {
				return nil, ErrPFX
			}
			out.Certificate = cert
		} else {
			out.Chain = append(out.Chain, cert)
		}
	}
	if out.Certificate == nil {
		return nil, ErrPFX
	}
	return out, nil
}

func explicit(der []byte) asn1.RawValue {
	return asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: der}
}

func matchKeyCertificate(key *gost3410.PrivateKey, certificate *gostx509.Certificate) error {
	if key == nil || certificate == nil {
		return ErrPFX
	}
	derived, err := key.PublicKey()
	if err != nil {
		return err
	}
	certPub, ok := certificate.PublicKey.(*gost3410.PublicKey)
	if !ok || !derived.Equal(certPub) {
		return ErrPFX
	}
	return nil
}

func marshalMaskedKey(key *gost3410.PrivateKey) ([]byte, error) {
	der, err := gostx509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	var info struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
		Attributes []asn1.RawValue `asn1:"optional,tag:0"`
		PublicKey  asn1.BitString  `asn1:"optional,tag:1"`
	}
	rest, err := asn1.Unmarshal(der, &info)
	if err != nil || len(rest) != 0 || info.Version != 1 {
		return nil, ErrPFX
	}
	mask, err := rand.Int(rand.Reader, key.C.Q)
	if err != nil {
		return nil, err
	}
	for mask.Sign() == 0 {
		mask, err = rand.Int(rand.Reader, key.C.Q)
		if err != nil {
			return nil, err
		}
	}
	inverse := new(big.Int).ModInverse(mask, key.C.Q)
	if inverse == nil {
		return nil, ErrPFX
	}
	masked := new(big.Int).Mul(key.Key, inverse)
	masked.Mod(masked, key.C.Q)
	if masked.Sign() == 0 {
		return nil, ErrPFX
	}
	pointSize := key.C.PointSize()
	info.PrivateKey = make([]byte, 2*pointSize)
	masked.FillBytes(info.PrivateKey[:pointSize])
	mask.FillBytes(info.PrivateKey[pointSize:])
	for _, part := range [][]byte{info.PrivateKey[:pointSize], info.PrivateKey[pointSize:]} {
		for i, j := 0, len(part)-1; i < j; i, j = i+1, j-1 {
			part[i], part[j] = part[j], part[i]
		}
	}
	out, err := asn1.Marshal(info)
	clear(info.PrivateKey)
	clear(der)
	return out, err
}
