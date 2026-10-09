package cms

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"hash"
	"io"
	"math/big"
	"strings"
	"time"

	"gitverse.ru/uzer_007/gogost/v3/gost28147"
	"gitverse.ru/uzer_007/gogost/v3/gost3410"
	"gitverse.ru/uzer_007/gogost/v3/gost34112012256"
	"gitverse.ru/uzer_007/gogost/v3/gost34112012512"
	"gitverse.ru/uzer_007/gogost/v3/gost341194"
	"gitverse.ru/uzer_007/gogost/v3/gostx509"
)

var (
	oidData               = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidContentType        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidSigningCertV2      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	oidDigest2001         = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 9}
	oidSign2001           = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 19}
	oidPublicKey2012256   = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 1}
	oidPublicKey2012512   = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 2}
	oidDigest256          = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 2}
	oidDigest512          = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 3}
	oidSign256            = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 3, 2}
	oidSign512            = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 3, 3}
	oidSHA256             = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA512             = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidRSAEncryption      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSHA256WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA512WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidECDSAWithSHA256    = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA512    = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidTSTInfo            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidSignatureTimeStamp = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}

	ErrSignedData = errors.New("gogost/cms: Некорректный SignedData")
	ErrSignature  = errors.New("gogost/cms: Подпись не прошла проверку")
)

// SignedData is a CMS ContentInfo containing SignedData. Content and the
// encoded certificate fields reference the input passed to ParseSignedData.
// Keep that input alive and unchanged for the lifetime of this value.
type SignedData struct {
	Content      []byte
	ContentType  asn1.ObjectIdentifier
	Detached     bool
	Certificates []*gostx509.Certificate
	Signers      []SignerInfo
	contentParts [][]byte
}

// ContentReader returns the embedded content without copying its segments.
// The input passed to ParseSignedData must remain alive and unchanged.
func (s *SignedData) ContentReader() (io.Reader, error) {
	if s == nil || s.Detached {
		return nil, ErrSignedData
	}
	if len(s.contentParts) == 0 {
		return bytes.NewReader(s.Content), nil
	}
	readers := make([]io.Reader, len(s.contentParts))
	for i, part := range s.contentParts {
		readers[i] = bytes.NewReader(part)
	}
	return io.MultiReader(readers...), nil
}

// SignerInfo describes one CMS signer. The certificate is selected by its
// issuer and serial number; possession of it does not establish trust.
type SignerInfo struct {
	Certificate         *gostx509.Certificate
	DigestAlgorithm     asn1.ObjectIdentifier
	SignatureAlgorithm  asn1.ObjectIdentifier
	Signature           []byte
	SignatureTimeStamps []*TimeStampToken
	SigningTime         time.Time
	issuer              []byte
	serial              *big.Int
	signedAttrs         []byte
	messageDigest       []byte
	certHash            []byte
	certHashAlgorithm   asn1.ObjectIdentifier
}

// SignerResult reports cryptographic validity for one signer. Trust in the
// certificate chain must be checked separately with gostx509.Certificate.Verify.
type SignerResult struct {
	Signer *SignerInfo
	Err    error
}

// SignDetached creates a DER CMS detached signature for a short message.
func SignDetached(content []byte, cert *gostx509.Certificate, signer crypto.Signer) ([]byte, error) {
	return SignDetachedWithOptions(content, cert, signer, nil)
}

// SignDetachedWithOptions creates a detached signature with explicit CMS options.
func SignDetachedWithOptions(content []byte, cert *gostx509.Certificate, signer crypto.Signer, options *SignOptions) ([]byte, error) {
	return SignDetachedReaderWithOptions(bytes.NewReader(content), cert, signer, options)
}

// SignDetachedReader hashes the content in one pass without retaining it.
func SignDetachedReader(content io.Reader, cert *gostx509.Certificate, signer crypto.Signer) ([]byte, error) {
	return SignDetachedReaderWithOptions(content, cert, signer, nil)
}

// SignDetachedReaderWithOptions signs a stream without retaining its content.
func SignDetachedReaderWithOptions(content io.Reader, cert *gostx509.Certificate, signer crypto.Signer, options *SignOptions) ([]byte, error) {
	contentType, err := signContentType(options)
	if err != nil {
		return nil, err
	}
	digestOID, _, h, err := signerProfile(cert, signer)
	if err != nil {
		return nil, err
	}
	if content == nil {
		return nil, ErrSignedData
	}
	if _, err = io.Copy(h, content); err != nil {
		return nil, err
	}
	return signHashedWithOptions(nil, false, cert, signer, digestOID, contentType, h.Sum(nil), options)
}

// SignAttached creates a DER CMS signature with content embedded.
func SignAttached(content []byte, cert *gostx509.Certificate, signer crypto.Signer) ([]byte, error) {
	return SignAttachedWithOptions(content, cert, signer, nil)
}

// SignAttachedWithOptions creates an attached signature with explicit CMS options.
func SignAttachedWithOptions(content []byte, cert *gostx509.Certificate, signer crypto.Signer, options *SignOptions) ([]byte, error) {
	if len(content) > maxCMSSize/2 {
		return nil, ErrSignedData
	}
	contentType, err := signContentType(options)
	if err != nil {
		return nil, err
	}
	digestOID, _, h, err := signerProfile(cert, signer)
	if err != nil {
		return nil, err
	}
	_, _ = h.Write(content)
	return signHashedWithOptions(content, true, cert, signer, digestOID, contentType, h.Sum(nil), options)
}

// SignAttachedTo writes BER SignedData with constructed content in bounded
// chunks. On read or write failure, w may contain a partial CMS object.
func SignAttachedTo(w io.Writer, content io.Reader, cert *gostx509.Certificate, signer crypto.Signer) error {
	return SignAttachedToWithOptions(w, content, cert, signer, nil)
}

// SignAttachedToWithOptions writes BER SignedData with explicit CMS options.
func SignAttachedToWithOptions(w io.Writer, content io.Reader, cert *gostx509.Certificate, signer crypto.Signer, options *SignOptions) error {
	if w == nil || content == nil {
		return ErrSignedData
	}
	contentType, err := signContentType(options)
	if err != nil {
		return err
	}
	digestOID, _, h, err := signerProfile(cert, signer)
	if err != nil {
		return err
	}
	certSet, err := signedCertificateSet(cert, options)
	if err != nil {
		return err
	}
	prefix := [][]byte{
		{0x30, 0x80}, derOID(oidSignedData), {0xa0, 0x80},
		{0x30, 0x80}, signedDataVersion(contentType),
		derSet(cmsSignatureAlgorithmDER(digestOID)),
		{0x30, 0x80}, derOID(contentType), {0xa0, 0x80}, {0x24, 0x80},
	}
	for _, piece := range prefix {
		if err := writeCMS(w, piece); err != nil {
			return err
		}
	}
	var chunk [32 << 10]byte
	var total int64
	for {
		n, readErr := io.ReadFull(content, chunk[:])
		if n > 0 {
			total += int64(n)
			if total > maxCMSSize/2 {
				return ErrSignedData
			}
			_, _ = h.Write(chunk[:n])
			if err := writeCMS(w, []byte{0x04}); err != nil {
				return err
			}
			if err := writeCMS(w, derLength(n)); err != nil {
				return err
			}
			if err := writeCMS(w, chunk[:n]); err != nil {
				return err
			}
		}
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	for i := 0; i < 3; i++ { // OCTET STRING, [0] content, encapContentInfo
		if err := writeCMS(w, []byte{0, 0}); err != nil {
			return err
		}
	}
	info, err := signerInfoHashedWithOptions(cert, signer, digestOID, contentType, h.Sum(nil), options)
	if err != nil {
		return err
	}
	if err := writeCMS(w, certSet); err != nil {
		return err
	}
	if err := writeCMS(w, derSet(info)); err != nil {
		return err
	}
	for i := 0; i < 3; i++ { // SignedData, [0] wrapper, ContentInfo
		if err := writeCMS(w, []byte{0, 0}); err != nil {
			return err
		}
	}
	return nil
}

func signerProfile(cert *gostx509.Certificate, signer crypto.Signer) (asn1.ObjectIdentifier, asn1.ObjectIdentifier, hash.Hash, error) {
	if cert == nil || len(cert.Raw) == 0 || signer == nil {
		return nil, nil, nil, ErrSignedData
	}
	pub, ok := cert.PublicKey.(*gost3410.PublicKey)
	if !ok || pub == nil || pub.C == nil {
		return nil, nil, nil, gostx509.ErrUnsupportedAlgorithm
	}
	signerPub, ok := signer.Public().(*gost3410.PublicKey)
	if !ok || !pub.Equal(signerPub) {
		return nil, nil, nil, errors.New("gogost/cms: Ключ подписанта не соответствует сертификату")
	}
	if strings.Contains(pub.C.Name, "2001") {
		return oidDigest2001, oidSign2001, gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet), nil
	}
	if pub.C.PointSize() == 32 {
		return oidDigest256, oidSign256, gost34112012256.New(), nil
	}
	if pub.C.PointSize() == 64 {
		return oidDigest512, oidSign512, gost34112012512.New(), nil
	}
	return nil, nil, nil, gostx509.ErrUnsupportedAlgorithm
}

func digestForOID(oid asn1.ObjectIdentifier) (hash.Hash, error) {
	switch {
	case oid.Equal(oidSHA256):
		return sha256.New(), nil
	case oid.Equal(oidSHA512):
		return sha512.New(), nil
	case oid.Equal(oidDigest2001):
		return gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet), nil
	case oid.Equal(oidDigest256):
		return gost34112012256.New(), nil
	case oid.Equal(oidDigest512):
		return gost34112012512.New(), nil
	default:
		return nil, gostx509.ErrUnsupportedAlgorithm
	}
}

func makeAttribute(oid asn1.ObjectIdentifier, value []byte) []byte {
	return derWrap(0x30, derOID(oid), derWrap(0x31, value))
}

func cmsSignatureAlgorithmDER(oid asn1.ObjectIdentifier) []byte {
	if oid.Equal(oidSign2001) || oid.Equal(oidDigest2001) {
		return derWrap(0x30, derOID(oid), []byte{0x05, 0x00})
	}
	return algorithmDER(oid)
}

func makeSignedAttributes(cert *gostx509.Certificate, contentType asn1.ObjectIdentifier, contentDigest []byte) ([]byte, error) {
	return makeSignedAttributesWithOptions(cert, contentType, contentDigest, nil)
}

func makeSignedAttributesWithOptions(cert *gostx509.Certificate, contentType asn1.ObjectIdentifier, contentDigest []byte, options *SignOptions) ([]byte, error) {
	certHash := gost34112012256.New()
	_, _ = certHash.Write(cert.Raw)
	essID := derWrap(0x30, algorithmDER(oidDigest256), derWrap(0x04, certHash.Sum(nil)))
	ess := derWrap(0x30, derWrap(0x30, essID))
	attrs := [][]byte{
		makeAttribute(oidContentType, derOID(contentType)),
		makeAttribute(oidMessageDigest, derWrap(0x04, contentDigest)),
		makeAttribute(oidSigningCertV2, ess),
	}
	if options != nil && options.OmitSigningTime {
		if options.SigningTime != nil {
			return nil, ErrSignedData
		}
	} else {
		stamp := time.Now()
		if options != nil && options.SigningTime != nil {
			stamp = *options.SigningTime
		}
		timeDER, err := asn1.Marshal(stamp.UTC().Truncate(time.Second))
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, makeAttribute(oidSigningTime, timeDER))
	}
	return derSet(attrs...), nil
}

func signHashed(content []byte, attached bool, cert *gostx509.Certificate, signer crypto.Signer, digestOID, contentType asn1.ObjectIdentifier, contentDigest []byte) ([]byte, error) {
	return signHashedWithOptions(content, attached, cert, signer, digestOID, contentType, contentDigest, nil)
}

func signHashedWithOptions(content []byte, attached bool, cert *gostx509.Certificate, signer crypto.Signer, digestOID, contentType asn1.ObjectIdentifier, contentDigest []byte, options *SignOptions) ([]byte, error) {
	signerInfo, err := signerInfoHashedWithOptions(cert, signer, digestOID, contentType, contentDigest, options)
	if err != nil {
		return nil, err
	}
	certSet, err := signedCertificateSet(cert, options)
	if err != nil {
		return nil, err
	}
	eci := derOID(contentType)
	if attached {
		eci = append(eci, derWrap(0xa0, derWrap(0x04, content))...)
	}
	signed := derWrap(0x30, signedDataVersion(contentType),
		derSet(cmsSignatureAlgorithmDER(digestOID)), derWrap(0x30, eci),
		certSet, derSet(signerInfo))
	return derWrap(0x30, derOID(oidSignedData), derWrap(0xa0, signed)), nil
}

func signerInfoHashed(cert *gostx509.Certificate, signer crypto.Signer, digestOID, contentType asn1.ObjectIdentifier, contentDigest []byte) ([]byte, error) {
	return signerInfoHashedWithOptions(cert, signer, digestOID, contentType, contentDigest, nil)
}

func signerInfoHashedWithOptions(cert *gostx509.Certificate, signer crypto.Signer, digestOID, contentType asn1.ObjectIdentifier, contentDigest []byte, options *SignOptions) ([]byte, error) {
	_, signOID, _, err := signerProfile(cert, signer)
	if err != nil {
		return nil, err
	}
	attrs, err := makeSignedAttributesWithOptions(cert, contentType, contentDigest, options)
	if err != nil {
		return nil, err
	}
	h, _ := digestForOID(digestOID)
	_, _ = h.Write(attrs)
	digest := h.Sum(nil)
	// The underlying gost3410.PrivateKey accepts the scalar in the opposite
	// byte order from the CMS/PKIX digest. Its reverse-digest adapter already
	// implements the wire convention.
	if raw, ok := signer.(*gost3410.PrivateKey); ok {
		signer = &gost3410.PrivateKeyReverseDigest{Prv: raw}
	}
	if adapter, ok := signer.(*gost3410.PrivateKeyReverseDigestAndSignature); ok {
		signer = &gost3410.PrivateKeyReverseDigest{Prv: adapter.Prv}
	}
	signature, err := signer.Sign(rand.Reader, digest, crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	issuerSerial := derWrap(0x30, cert.RawIssuer, mustASN1(cert.SerialNumber))
	// signedAttrs is [0] IMPLICIT SET OF: its contents are identical to the
	// canonical DER SET OF used as signature input.
	_, _, attrContent, _, err := readDER(attrs)
	if err != nil {
		return nil, err
	}
	return derWrap(0x30, []byte{0x02, 0x01, 0x01}, issuerSerial,
		cmsSignatureAlgorithmDER(digestOID), derWrap(0xa0, attrContent),
		cmsSignatureAlgorithmDER(signOID), derWrap(0x04, signature)), nil
}

func mustASN1(value any) []byte {
	out, _ := asn1.Marshal(value)
	return out
}

// ParseSignedData reads DER CMS SignedData. It rejects unknown top-level
// content types, excessive counts, malformed tags and noncanonical attributes.
func ParseSignedData(der []byte) (*SignedData, error) {
	return parseSignedData(der, 0)
}

func parseSignedData(der []byte, depth int) (*SignedData, error) {
	if depth > 4 || len(der) == 0 || len(der) > maxCMSSize {
		return nil, ErrSignedData
	}
	_, outer, rest, err := readExpectedBER(der, 0x30)
	if err != nil || len(rest) != 0 {
		return nil, ErrSignedData
	}
	oid, tail, err := parseOID(outer)
	if err != nil || !oid.Equal(oidSignedData) {
		return nil, ErrSignedData
	}
	_, explicit, tail, err := readExpectedBER(tail, 0xa0)
	if err != nil || len(tail) != 0 {
		return nil, ErrSignedData
	}
	_, body, tail, err := readExpectedBER(explicit, 0x30)
	if err != nil || len(tail) != 0 {
		return nil, ErrSignedData
	}
	version, body, err := parseSmallInt(body)
	if err != nil || (version != 1 && version != 3) {
		return nil, ErrSignedData
	}
	_, algorithms, body, err := readExpectedBER(body, 0x31)
	if err != nil {
		return nil, ErrSignedData
	}
	digestSet := make(map[string]bool)
	for len(algorithms) != 0 {
		a, next, e := parseAlgorithm(algorithms)
		if e != nil || len(digestSet) >= maxCMSSigners {
			return nil, ErrSignedData
		}
		digestSet[a.String()] = true
		algorithms = next
	}
	_, encap, body, err := readExpectedBER(body, 0x30)
	if err != nil {
		return nil, ErrSignedData
	}
	contentOID, encap, err := parseOID(encap)
	if err != nil {
		return nil, ErrSignedData
	}
	result := &SignedData{ContentType: contentOID, Detached: len(encap) == 0}
	if len(encap) != 0 {
		_, econtent, tail, e := readExpectedBER(encap, 0xa0)
		if e != nil || len(tail) != 0 {
			return nil, ErrSignedData
		}
		tag, _, octets, rest, e := readBER(econtent, 0)
		if e != nil || len(rest) != 0 {
			return nil, ErrSignedData
		}
		result.contentParts, e = octetSegments(tag, octets, 0, nil)
		if e != nil {
			return nil, ErrSignedData
		}
		if len(result.contentParts) == 1 {
			result.Content = result.contentParts[0]
		}
	}
	if len(body) != 0 && body[0] == 0xa0 {
		_, certs, next, e := readExpectedBER(body, 0xa0)
		if e != nil {
			return nil, ErrSignedData
		}
		for len(certs) != 0 {
			if len(result.Certificates) >= maxCMSCertificates {
				return nil, ErrSignedData
			}
			full, _, rest, e := readExpected(certs, 0x30)
			if e != nil {
				return nil, ErrSignedData
			}
			cert, e := gostx509.ParseCertificate(full)
			if e != nil {
				return nil, e
			}
			result.Certificates = append(result.Certificates, cert)
			certs = rest
		}
		body = next
	}
	if len(body) != 0 && body[0] == 0xa1 {
		_, _, body, err = readExpectedBER(body, 0xa1)
		if err != nil {
			return nil, ErrSignedData
		}
	}
	_, infos, tail, err := readExpectedBER(body, 0x31)
	if err != nil || len(tail) != 0 {
		return nil, ErrSignedData
	}
	for len(infos) != 0 {
		if len(result.Signers) >= maxCMSSigners {
			return nil, ErrSignedData
		}
		_, signerBody, next, e := readExpectedBER(infos, 0x30)
		if e != nil {
			return nil, ErrSignedData
		}
		info, e := parseSignerInfo(signerBody, result.Certificates, contentOID, depth)
		if e != nil || !digestSet[info.DigestAlgorithm.String()] {
			return nil, ErrSignedData
		}
		result.Signers = append(result.Signers, info)
		infos = next
	}
	return result, nil
}

func parseSignerInfo(body []byte, certs []*gostx509.Certificate, contentOID asn1.ObjectIdentifier, depth int) (SignerInfo, error) {
	var info SignerInfo
	version, body, err := parseSmallInt(body)
	if err != nil || version != 1 {
		return info, ErrSignedData
	}
	_, sid, body, err := readExpected(body, 0x30)
	if err != nil {
		return info, ErrSignedData
	}
	info.issuer, _, sid, err = readExpected(sid, 0x30)
	if err != nil {
		return info, ErrSignedData
	}
	serialDER, _, sid, err := readExpected(sid, 0x02)
	if err != nil || len(sid) != 0 {
		return info, ErrSignedData
	}
	if _, err = asn1.Unmarshal(serialDER, &info.serial); err != nil || info.serial == nil || info.serial.Sign() <= 0 {
		return info, ErrSignedData
	}
	for _, cert := range certs {
		if bytes.Equal(info.issuer, cert.RawIssuer) && info.serial.Cmp(cert.SerialNumber) == 0 {
			info.Certificate = cert
			break
		}
	}
	info.DigestAlgorithm, body, err = parseAlgorithm(body)
	if err != nil {
		return info, ErrSignedData
	}
	if len(body) != 0 && body[0] == 0xa0 {
		_, attrs, next, e := readExpected(body, 0xa0)
		if e != nil {
			return info, ErrSignedData
		}
		info.signedAttrs = derWrap(0x31, attrs)
		if e = parseSignedAttrs(&info, attrs, contentOID); e != nil {
			return info, e
		}
		body = next
	}
	info.SignatureAlgorithm, body, err = parseAlgorithm(body)
	if err != nil {
		return info, ErrSignedData
	}
	_, info.Signature, body, err = readExpected(body, 0x04)
	if err != nil {
		return info, ErrSignedData
	}
	if len(body) != 0 {
		if body[0] != 0xa1 {
			return info, ErrSignedData
		}
		_, unsigned, next, e := readExpected(body, 0xa1)
		if e != nil {
			return info, ErrSignedData
		}
		if e = parseUnsignedAttrs(&info, unsigned, depth); e != nil {
			return info, e
		}
		body = next
		if err != nil || len(body) != 0 {
			return info, ErrSignedData
		}
	}
	return info, nil
}

func parseUnsignedAttrs(info *SignerInfo, attrs []byte, depth int) error {
	count := 0
	for len(attrs) != 0 {
		_, body, rest, err := readExpected(attrs, 0x30)
		if err != nil || count >= 32 {
			return ErrSignedData
		}
		count++
		oid, body, err := parseOID(body)
		if err != nil {
			return ErrSignedData
		}
		_, values, tail, err := readExpected(body, 0x31)
		if err != nil || len(tail) != 0 {
			return ErrSignedData
		}
		if oid.Equal(oidSignatureTimeStamp) {
			for len(values) != 0 {
				if len(info.SignatureTimeStamps) >= 16 {
					return ErrSignedData
				}
				full, _, next, e := readExpected(values, 0x30)
				if e != nil {
					return ErrSignedData
				}
				token, e := parseTimeStampToken(full, depth+1)
				if e != nil {
					return e
				}
				info.SignatureTimeStamps = append(info.SignatureTimeStamps, token)
				values = next
			}
			if len(info.SignatureTimeStamps) == 0 {
				return ErrSignedData
			}
		}
		attrs = rest
	}
	return nil
}

func parseSignedAttrs(info *SignerInfo, attrs []byte, contentOID asn1.ObjectIdentifier) error {
	var seen [32]asn1.ObjectIdentifier
	count := 0
	var previous []byte
	hasContentType, hasMessageDigest := false, false
	for len(attrs) != 0 {
		full, body, rest, err := readExpected(attrs, 0x30)
		if err != nil || count >= len(seen) || previous != nil && bytes.Compare(previous, full) >= 0 {
			return ErrSignedData
		}
		previous = full
		oid, body, err := parseOID(body)
		if err != nil {
			return ErrSignedData
		}
		for _, prior := range seen[:count] {
			if oid.Equal(prior) {
				return ErrSignedData
			}
		}
		seen[count] = oid
		count++
		_, values, body, err := readExpected(body, 0x31)
		if err != nil || len(body) != 0 {
			return ErrSignedData
		}
		value, _, _, remain, err := readDER(values)
		if err != nil || len(remain) != 0 {
			return ErrSignedData
		}
		switch {
		case oid.Equal(oidContentType):
			hasContentType = true
			if value != 0x06 {
				return ErrSignedData
			}
			contentType, _, e := parseOID(values)
			if e != nil || !contentType.Equal(contentOID) {
				return ErrSignedData
			}
		case oid.Equal(oidMessageDigest):
			hasMessageDigest = true
			_, info.messageDigest, _, err = readExpected(values, 0x04)
			if err != nil {
				return ErrSignedData
			}
		case oid.Equal(oidSigningTime):
			if _, err = asn1.Unmarshal(values, &info.SigningTime); err != nil {
				return ErrSignedData
			}
		case oid.Equal(oidSigningCertV2):
			info.certHash, info.certHashAlgorithm, err = parseSigningCertV2(values)
			if err != nil {
				return err
			}
		}
		attrs = rest
	}
	if !hasContentType || !hasMessageDigest {
		return ErrSignedData
	}
	return nil
}

func parseSigningCertV2(in []byte) ([]byte, asn1.ObjectIdentifier, error) {
	_, body, rest, err := readExpected(in, 0x30)
	if err != nil || len(rest) != 0 {
		return nil, nil, ErrSignedData
	}
	_, ids, body, err := readExpected(body, 0x30)
	if err != nil {
		return nil, nil, ErrSignedData
	}
	if len(body) != 0 {
		_, _, body, err = readExpected(body, 0x30) // optional policies
		if err != nil || len(body) != 0 {
			return nil, nil, ErrSignedData
		}
	}
	_, id, remainingIDs, err := readExpected(ids, 0x30)
	if err != nil {
		return nil, nil, ErrSignedData
	}
	for count := 1; len(remainingIDs) != 0; count++ {
		if count >= maxCMSCertificates {
			return nil, nil, ErrSignedData
		}
		_, _, remainingIDs, err = readExpected(remainingIDs, 0x30)
		if err != nil {
			return nil, nil, ErrSignedData
		}
	}
	hashOID := oidSHA256
	if len(id) != 0 && id[0] == 0x30 {
		hashOID, id, err = parseAlgorithm(id)
		if err != nil || !hashOID.Equal(oidDigest256) && !hashOID.Equal(oidSHA256) {
			return nil, nil, ErrSignedData
		}
	}
	_, digest, tail, err := readExpected(id, 0x04)
	if err != nil || len(digest) != sha256.Size {
		return nil, nil, ErrSignedData
	}
	if len(tail) != 0 {
		_, _, tail, err = readExpected(tail, 0x30) // optional issuerSerial
		if err != nil || len(tail) != 0 {
			return nil, nil, ErrSignedData
		}
	}
	return digest, hashOID, nil
}

// Verify checks every signer against embedded certificates. It does not
// verify certificate chains or assign trust to embedded certificates.
func (s *SignedData) Verify(detached []byte) ([]SignerResult, error) {
	if s != nil && !s.Detached {
		if detached != nil {
			return nil, ErrSignedData
		}
		return s.VerifyReader(nil)
	}
	return s.VerifyReader(bytes.NewReader(detached))
}

// VerifyReaderWithCertificates checks signatures when the CMS message omits
// signer certificates. External certificates are used only as candidate
// public keys; the caller must validate their trust chains separately.
func (s *SignedData) VerifyReaderWithCertificates(detached io.Reader, external []*gostx509.Certificate) ([]SignerResult, error) {
	if s == nil {
		return nil, ErrSignedData
	}
	copyOf := *s
	copyOf.Signers = append([]SignerInfo(nil), s.Signers...)
	for i := range copyOf.Signers {
		info := &copyOf.Signers[i]
		if info.Certificate != nil {
			continue
		}
		for _, cert := range external {
			if cert != nil && cert.SerialNumber != nil && bytes.Equal(info.issuer, cert.RawIssuer) && info.serial.Cmp(cert.SerialNumber) == 0 {
				info.Certificate = cert
				break
			}
		}
	}
	return copyOf.VerifyReader(detached)
}

// VerifyReader hashes detached content in one pass, regardless of its size.
// Pass nil only for attached SignedData.
func (s *SignedData) VerifyReader(detached io.Reader) ([]SignerResult, error) {
	if s == nil || s.Detached && detached == nil || !s.Detached && detached != nil {
		return nil, ErrSignedData
	}
	if !s.Detached {
		var err error
		detached, err = s.ContentReader()
		if err != nil {
			return nil, err
		}
	}
	results := make([]SignerResult, len(s.Signers))
	hashes := make([]hash.Hash, len(s.Signers))
	writers := make([]io.Writer, 0, len(s.Signers))
	for i := range s.Signers {
		results[i].Signer = &s.Signers[i]
		var err error
		hashes[i], err = digestForOID(s.Signers[i].DigestAlgorithm)
		if err != nil {
			results[i].Err = err
			continue
		}
		writers = append(writers, hashes[i])
	}
	if _, err := io.Copy(io.MultiWriter(writers...), detached); err != nil {
		return nil, err
	}
	for i := range s.Signers {
		if results[i].Err != nil {
			continue
		}
		info := &s.Signers[i]
		contentHash := hashes[i].Sum(nil)
		if info.Certificate == nil {
			results[i].Err = errors.New("gogost/cms: Сертификат подписанта отсутствует")
			continue
		}
		if len(info.signedAttrs) != 0 {
			if !bytes.Equal(contentHash, info.messageDigest) {
				results[i].Err = ErrSignature
				continue
			}
			if len(info.certHash) != 0 {
				var expected []byte
				switch {
				case info.certHashAlgorithm.Equal(oidSHA256):
					sum := sha256.Sum256(info.Certificate.Raw)
					expected = sum[:]
				case info.certHashAlgorithm.Equal(oidDigest256):
					h := gost34112012256.New()
					_, _ = h.Write(info.Certificate.Raw)
					expected = h.Sum(nil)
				default:
					results[i].Err = gostx509.ErrUnsupportedAlgorithm
					continue
				}
				if !bytes.Equal(expected, info.certHash) {
					results[i].Err = ErrSignature
					continue
				}
			}
			hashes[i].Reset()
			_, _ = hashes[i].Write(info.signedAttrs)
			contentHash = hashes[i].Sum(nil)
		}
		results[i].Err = verifyCMSSignature(info, contentHash)
	}
	return results, nil
}

func verifyCMSSignature(info *SignerInfo, digest []byte) error {
	switch pub := info.Certificate.PublicKey.(type) {
	case *gost3410.PublicKey:
		if pub == nil || !compatibleSignatureOID(info.DigestAlgorithm, info.SignatureAlgorithm, pub) {
			return gostx509.ErrUnsupportedAlgorithm
		}
		verified, err := (gost3410.PublicKeyReverseDigest{Pub: pub}).VerifyDigest(digest, info.Signature)
		if err != nil {
			return err
		}
		if !verified {
			return ErrSignature
		}
		return nil
	case *rsa.PublicKey:
		var algorithm crypto.Hash
		switch {
		case info.DigestAlgorithm.Equal(oidSHA256) &&
			(info.SignatureAlgorithm.Equal(oidRSAEncryption) || info.SignatureAlgorithm.Equal(oidSHA256WithRSA)):
			algorithm = crypto.SHA256
		case info.DigestAlgorithm.Equal(oidSHA512) &&
			(info.SignatureAlgorithm.Equal(oidRSAEncryption) || info.SignatureAlgorithm.Equal(oidSHA512WithRSA)):
			algorithm = crypto.SHA512
		default:
			return gostx509.ErrUnsupportedAlgorithm
		}
		if err := rsa.VerifyPKCS1v15(pub, algorithm, digest, info.Signature); err != nil {
			return ErrSignature
		}
		return nil
	case *ecdsa.PublicKey:
		if !(info.DigestAlgorithm.Equal(oidSHA256) && info.SignatureAlgorithm.Equal(oidECDSAWithSHA256) ||
			info.DigestAlgorithm.Equal(oidSHA512) && info.SignatureAlgorithm.Equal(oidECDSAWithSHA512)) {
			return gostx509.ErrUnsupportedAlgorithm
		}
		if !ecdsa.VerifyASN1(pub, digest, info.Signature) {
			return ErrSignature
		}
		return nil
	default:
		return gostx509.ErrUnsupportedAlgorithm
	}
}

func compatibleSignatureOID(digest, signature asn1.ObjectIdentifier, pub *gost3410.PublicKey) bool {
	switch {
	case signature.Equal(oidSign2001):
		return digest.Equal(oidDigest2001) && pub.C.PointSize() == 32
	case signature.Equal(oidSign256), signature.Equal(oidPublicKey2012256):
		return digest.Equal(oidDigest256) && pub.C.PointSize() == 32
	case signature.Equal(oidSign512), signature.Equal(oidPublicKey2012512):
		return digest.Equal(oidDigest512) && pub.C.PointSize() == 64
	default:
		return false
	}
}
