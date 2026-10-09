// Package gostx509 extends crypto/x509 with GOST R 34.10-2012 keys and
// signatures while retaining the familiar standard-library API.
package gostx509

import (
	"bytes"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"time"
)

// Certificate has the same representation as crypto/x509.Certificate. A
// distinct type lets this package add GOST-aware verification methods.
type Certificate stdx509.Certificate

type (
	SignatureAlgorithm  = stdx509.SignatureAlgorithm
	PublicKeyAlgorithm  = stdx509.PublicKeyAlgorithm
	KeyUsage            = stdx509.KeyUsage
	ExtKeyUsage         = stdx509.ExtKeyUsage
	InvalidReason       = stdx509.InvalidReason
	RevocationListEntry = stdx509.RevocationListEntry
	OID                 = stdx509.OID
	PolicyMapping       = stdx509.PolicyMapping
)

// CertificateRequest extends the standard request with GOST signature checks.
type CertificateRequest stdx509.CertificateRequest

// RevocationList extends the standard CRL with GOST signature verification.
type RevocationList stdx509.RevocationList

const (
	UnknownSignatureAlgorithm = stdx509.UnknownSignatureAlgorithm
	MD2WithRSA                = stdx509.MD2WithRSA
	MD5WithRSA                = stdx509.MD5WithRSA
	SHA1WithRSA               = stdx509.SHA1WithRSA
	SHA256WithRSA             = stdx509.SHA256WithRSA
	SHA384WithRSA             = stdx509.SHA384WithRSA
	SHA512WithRSA             = stdx509.SHA512WithRSA
	DSAWithSHA1               = stdx509.DSAWithSHA1
	DSAWithSHA256             = stdx509.DSAWithSHA256
	ECDSAWithSHA1             = stdx509.ECDSAWithSHA1
	ECDSAWithSHA256           = stdx509.ECDSAWithSHA256
	ECDSAWithSHA384           = stdx509.ECDSAWithSHA384
	ECDSAWithSHA512           = stdx509.ECDSAWithSHA512
	SHA256WithRSAPSS          = stdx509.SHA256WithRSAPSS
	SHA384WithRSAPSS          = stdx509.SHA384WithRSAPSS
	SHA512WithRSAPSS          = stdx509.SHA512WithRSAPSS
	PureEd25519               = stdx509.PureEd25519

	// GOST256 и GOST512 обозначают подписи ГОСТ Р 34.10-2012 со
	// Стрибогом-256 и Стрибогом-512. GOST2001 обозначает профиль
	// ГОСТ Р 34.10-2001 с ГОСТ Р 34.11-94.
	GOST256 SignatureAlgorithm = 1000 + iota
	GOST512
	GOST2001
)

const (
	MLDSA44 = stdx509.MLDSA44
	MLDSA65 = stdx509.MLDSA65
	MLDSA87 = stdx509.MLDSA87
)

const (
	UnknownPublicKeyAlgorithm = stdx509.UnknownPublicKeyAlgorithm
	RSA                       = stdx509.RSA
	DSA                       = stdx509.DSA
	ECDSA                     = stdx509.ECDSA
	Ed25519                   = stdx509.Ed25519
	MLDSA                     = stdx509.MLDSA

	// GOST identifies a GOST R 34.10 public key.
	GOST PublicKeyAlgorithm = 1000
)

const (
	KeyUsageDigitalSignature  = stdx509.KeyUsageDigitalSignature
	KeyUsageContentCommitment = stdx509.KeyUsageContentCommitment
	KeyUsageKeyEncipherment   = stdx509.KeyUsageKeyEncipherment
	KeyUsageDataEncipherment  = stdx509.KeyUsageDataEncipherment
	KeyUsageKeyAgreement      = stdx509.KeyUsageKeyAgreement
	KeyUsageCertSign          = stdx509.KeyUsageCertSign
	KeyUsageCRLSign           = stdx509.KeyUsageCRLSign
	KeyUsageEncipherOnly      = stdx509.KeyUsageEncipherOnly
	KeyUsageDecipherOnly      = stdx509.KeyUsageDecipherOnly
)

const (
	ExtKeyUsageAny                            = stdx509.ExtKeyUsageAny
	ExtKeyUsageServerAuth                     = stdx509.ExtKeyUsageServerAuth
	ExtKeyUsageClientAuth                     = stdx509.ExtKeyUsageClientAuth
	ExtKeyUsageCodeSigning                    = stdx509.ExtKeyUsageCodeSigning
	ExtKeyUsageEmailProtection                = stdx509.ExtKeyUsageEmailProtection
	ExtKeyUsageIPSECEndSystem                 = stdx509.ExtKeyUsageIPSECEndSystem
	ExtKeyUsageIPSECTunnel                    = stdx509.ExtKeyUsageIPSECTunnel
	ExtKeyUsageIPSECUser                      = stdx509.ExtKeyUsageIPSECUser
	ExtKeyUsageTimeStamping                   = stdx509.ExtKeyUsageTimeStamping
	ExtKeyUsageOCSPSigning                    = stdx509.ExtKeyUsageOCSPSigning
	ExtKeyUsageMicrosoftServerGatedCrypto     = stdx509.ExtKeyUsageMicrosoftServerGatedCrypto
	ExtKeyUsageNetscapeServerGatedCrypto      = stdx509.ExtKeyUsageNetscapeServerGatedCrypto
	ExtKeyUsageMicrosoftCommercialCodeSigning = stdx509.ExtKeyUsageMicrosoftCommercialCodeSigning
	ExtKeyUsageMicrosoftKernelCodeSigning     = stdx509.ExtKeyUsageMicrosoftKernelCodeSigning
)

const (
	NotAuthorizedToSign           = stdx509.NotAuthorizedToSign
	Expired                       = stdx509.Expired
	CANotAuthorizedForThisName    = stdx509.CANotAuthorizedForThisName
	TooManyIntermediates          = stdx509.TooManyIntermediates
	IncompatibleUsage             = stdx509.IncompatibleUsage
	NameMismatch                  = stdx509.NameMismatch
	NameConstraintsWithoutSANs    = stdx509.NameConstraintsWithoutSANs
	UnconstrainedName             = stdx509.UnconstrainedName
	TooManyConstraints            = stdx509.TooManyConstraints
	CANotAuthorizedForExtKeyUsage = stdx509.CANotAuthorizedForExtKeyUsage
)

type (
	CertificateInvalidError    = stdx509.CertificateInvalidError
	HostnameError              = stdx509.HostnameError
	UnknownAuthorityError      = stdx509.UnknownAuthorityError
	SystemRootsError           = stdx509.SystemRootsError
	ConstraintViolationError   = stdx509.ConstraintViolationError
	InsecureAlgorithmError     = stdx509.InsecureAlgorithmError
	UnhandledCriticalExtension = stdx509.UnhandledCriticalExtension
)

var ErrUnsupportedAlgorithm = stdx509.ErrUnsupportedAlgorithm

func asStandard(c *Certificate) *stdx509.Certificate {
	if c == nil {
		return nil
	}
	return (*stdx509.Certificate)(c)
}

func fromStandard(c *stdx509.Certificate) *Certificate {
	if c == nil {
		return nil
	}
	return (*Certificate)(c)
}

func toStandardChain(chain []*Certificate) []*stdx509.Certificate {
	result := make([]*stdx509.Certificate, len(chain))
	for i, cert := range chain {
		result[i] = asStandard(cert)
	}
	return result
}

func fromStandardChains(chains [][]*stdx509.Certificate) [][]*Certificate {
	result := make([][]*Certificate, len(chains))
	for i, chain := range chains {
		result[i] = make([]*Certificate, len(chain))
		for j, cert := range chain {
			result[i][j] = fromStandard(cert)
		}
	}
	return result
}

// Equal reports whether c and other contain the same DER certificate.
func (c *Certificate) Equal(other *Certificate) bool {
	if c == nil || other == nil {
		return c == other
	}
	return bytes.Equal(c.Raw, other.Raw)
}

// VerifyHostname checks whether c is valid for host.
func (c *Certificate) VerifyHostname(host string) error {
	return asStandard(c).VerifyHostname(host)
}

// CertPool is a set of trusted or intermediate certificates. Standard
// certificates are mirrored into crypto/x509 so ordinary chains retain the
// platform verifier; GOST certificates are kept for the GOST verifier.
type CertPool struct {
	standard *stdx509.CertPool
	certs    []*Certificate
	subjects [][]byte
}

// NewCertPool returns an empty certificate pool.
func NewCertPool() *CertPool {
	return &CertPool{standard: stdx509.NewCertPool()}
}

// SystemCertPool returns a copy of the platform root pool. Platform APIs do
// not expose their parsed certificates, so GOST roots must be added explicitly
// with AddCert or AppendCertsFromPEM.
func SystemCertPool() (*CertPool, error) {
	pool, err := stdx509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	return &CertPool{standard: pool}, nil
}

// AddCert adds cert to the pool.
func (p *CertPool) AddCert(cert *Certificate) {
	if cert == nil {
		panic("gostx509: adding nil Certificate to CertPool")
	}
	if p.standard == nil {
		p.standard = stdx509.NewCertPool()
	}
	for _, existing := range p.certs {
		if existing.Equal(cert) {
			return
		}
	}
	p.certs = append(p.certs, cert)
	p.subjects = append(p.subjects, append([]byte(nil), cert.RawSubject...))
	if cert.PublicKeyAlgorithm != GOST {
		p.standard.AddCert(asStandard(cert))
	}
}

// AppendCertsFromPEM parses and adds all CERTIFICATE blocks in pemCerts.
func (p *CertPool) AppendCertsFromPEM(pemCerts []byte) bool {
	ok := false
	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}
		cert, err := ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		p.AddCert(cert)
		ok = true
	}
	return ok
}

// Subjects returns the DER-encoded subjects of explicitly added certificates,
// followed by subjects from the platform pool.
func (p *CertPool) Subjects() [][]byte {
	if p == nil {
		return nil
	}
	result := make([][]byte, 0, len(p.subjects)+16)
	for _, subject := range p.subjects {
		result = append(result, append([]byte(nil), subject...))
	}
	if p.standard != nil {
		result = append(result, p.standard.Subjects()...)
	}
	return result
}

// Clone returns an independent copy of p.
func (p *CertPool) Clone() *CertPool {
	if p == nil {
		return nil
	}
	result := NewCertPool()
	if p.standard != nil {
		result.standard = p.standard.Clone()
	}
	for _, cert := range p.certs {
		result.certs = append(result.certs, cert)
	}
	for _, subject := range p.subjects {
		result.subjects = append(result.subjects, append([]byte(nil), subject...))
	}
	return result
}

// Equal reports whether p and other contain the same explicitly added
// certificates and the same standard pool.
func (p *CertPool) Equal(other *CertPool) bool {
	if p == nil || other == nil {
		return p == other
	}
	if len(p.certs) != len(other.certs) {
		return false
	}
	for _, cert := range p.certs {
		found := false
		for _, candidate := range other.certs {
			if cert.Equal(candidate) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if p.standard == nil || other.standard == nil {
		return p.standard == other.standard
	}
	return p.standard.Equal(other.standard)
}

// VerifyOptions contains parameters for Certificate.Verify.
type VerifyOptions struct {
	DNSName                   string
	Intermediates             *CertPool
	Roots                     *CertPool
	CurrentTime               time.Time
	KeyUsages                 []ExtKeyUsage
	MaxConstraintComparisions int
}

func (o VerifyOptions) standardOptions() stdx509.VerifyOptions {
	var roots, intermediates *stdx509.CertPool
	if o.Roots != nil {
		roots = o.Roots.standard
	}
	if o.Intermediates != nil {
		intermediates = o.Intermediates.standard
	}
	return stdx509.VerifyOptions{
		DNSName:                   o.DNSName,
		Intermediates:             intermediates,
		Roots:                     roots,
		CurrentTime:               o.CurrentTime,
		KeyUsages:                 o.KeyUsages,
		MaxConstraintComparisions: o.MaxConstraintComparisions,
	}
}

func invalidError(cert *Certificate, reason InvalidReason, detail string) error {
	return stdx509.CertificateInvalidError{
		Cert:   asStandard(cert),
		Reason: reason,
		Detail: detail,
	}
}

func unknownAuthority(cert *Certificate) error {
	return stdx509.UnknownAuthorityError{Cert: asStandard(cert)}
}

func unsupportedCriticalError(cert *Certificate) error {
	return stdx509.UnhandledCriticalExtension{}
}

var errNoRoots = errors.New("gostx509: no GOST trust roots configured")

// Name exposes pkix.Name in documentation without introducing a second type.
type Name = pkix.Name
