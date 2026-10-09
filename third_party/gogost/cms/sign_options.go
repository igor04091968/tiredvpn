package cms

import (
	"bytes"
	"encoding/asn1"
	"sort"
	"time"

	"gitverse.ru/uzer_007/gogost/v3/gostx509"
)

// SignOptions controls the CMS content type, signed time, and embedded
// certificate set. A nil options value uses id-data and the current UTC time.
type SignOptions struct {
	ContentType       asn1.ObjectIdentifier
	SigningTime       *time.Time
	OmitSigningTime   bool
	ExtraCertificates []*gostx509.Certificate
}

func signContentType(options *SignOptions) (asn1.ObjectIdentifier, error) {
	if options != nil && options.OmitSigningTime && options.SigningTime != nil {
		return nil, ErrSignedData
	}
	if options == nil || len(options.ContentType) == 0 {
		return oidData, nil
	}
	if len(options.ContentType) < 2 {
		return nil, ErrSignedData
	}
	if _, err := asn1.Marshal(options.ContentType); err != nil {
		return nil, ErrSignedData
	}
	return options.ContentType, nil
}

func signedDataVersion(contentType asn1.ObjectIdentifier) []byte {
	if contentType.Equal(oidData) {
		return []byte{0x02, 0x01, 0x01}
	}
	return []byte{0x02, 0x01, 0x03}
}

func signedCertificateSet(signer *gostx509.Certificate, options *SignOptions) ([]byte, error) {
	if signer == nil || len(signer.Raw) == 0 {
		return nil, ErrSignedData
	}
	if options == nil || len(options.ExtraCertificates) == 0 {
		return derWrap(0xa0, signer.Raw), nil
	}
	if len(options.ExtraCertificates) >= maxCMSCertificates {
		return nil, ErrSignedData
	}
	certs := make([][]byte, 0, 1+len(options.ExtraCertificates))
	certs = append(certs, signer.Raw)
	total := len(signer.Raw)
	for _, cert := range options.ExtraCertificates {
		if cert == nil || len(cert.Raw) == 0 {
			return nil, ErrSignedData
		}
		full, _, rest, err := readExpected(cert.Raw, 0x30)
		if err != nil || len(rest) != 0 || len(full) != len(cert.Raw) {
			return nil, ErrSignedData
		}
		duplicate := false
		for _, existing := range certs {
			if bytes.Equal(existing, cert.Raw) {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		total += len(cert.Raw)
		if total > maxCMSSize/2 {
			return nil, ErrSignedData
		}
		certs = append(certs, cert.Raw)
	}
	sort.Slice(certs, func(i, j int) bool { return bytes.Compare(certs[i], certs[j]) < 0 })
	return derWrap(0xa0, certs...), nil
}
