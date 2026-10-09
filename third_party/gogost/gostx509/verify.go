package gostx509

import (
	"bytes"
	stdx509 "crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"gitverse.ru/uzer_007/gogost/v3/gost3410"
)

// Keep the same work bound as crypto/x509. Most valid paths are far shorter;
// the headroom permits alternate parents with the same subject while bounding
// CPU spent on attacker-controlled chains.
const maxChainSignatureChecks = 100

var errSignatureLimit = errors.New("gostx509: signature check attempts limit reached while verifying certificate chain")

// CheckSignatureFrom verifies c's signature with parent's public key and
// enforces the CA and key-usage constraints required for certificate signing.
func (c *Certificate) CheckSignatureFrom(parent *Certificate) error {
	if parent.Version == 3 && !parent.BasicConstraintsValid ||
		parent.BasicConstraintsValid && !parent.IsCA {
		return stdx509.ConstraintViolationError{}
	}
	if parent.KeyUsage != 0 && parent.KeyUsage&KeyUsageCertSign == 0 {
		return stdx509.ConstraintViolationError{}
	}
	if parent.PublicKeyAlgorithm == UnknownPublicKeyAlgorithm {
		return ErrUnsupportedAlgorithm
	}
	return parent.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature)
}

// CheckSignature verifies signature over signed using c's public key.
func (c *Certificate) CheckSignature(algo SignatureAlgorithm, signed, signature []byte) error {
	if algo != GOST2001 && algo != GOST256 && algo != GOST512 {
		return asStandard(c).CheckSignature(algo, signed, signature)
	}
	pub, ok := c.PublicKey.(*gost3410.PublicKey)
	if !ok || c.PublicKeyAlgorithm != GOST {
		return fmt.Errorf("gostx509: GOST signature with public key %T", c.PublicKey)
	}
	if (algo == GOST2001 || algo == GOST256) && pub.C.PointSize() != 32 || algo == GOST512 && pub.C.PointSize() != 64 {
		return errors.New("gostx509: GOST signature and public-key sizes do not match")
	}
	digest, err := hashCertificate(algo, signed)
	if err != nil {
		return err
	}
	ok, err = (gost3410.PublicKeyReverseDigest{Pub: pub}).VerifyDigest(digest, signature)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("gostx509: GOST signature verification failure")
	}
	return nil
}

func (c *Certificate) isGOSTChainCertificate() bool {
	return c.PublicKeyAlgorithm == GOST || c.SignatureAlgorithm == GOST2001 || c.SignatureAlgorithm == GOST256 || c.SignatureAlgorithm == GOST512
}

func certInChain(chain []*Certificate, cert *Certificate) bool {
	for _, existing := range chain {
		if existing.Equal(cert) {
			return true
		}
	}
	return false
}

func candidatesBySubject(pool *CertPool, subject []byte) []*Certificate {
	if pool == nil {
		return nil
	}
	var result []*Certificate
	for _, cert := range pool.certs {
		if bytes.Equal(cert.RawSubject, subject) {
			result = append(result, cert)
		}
	}
	return result
}

func checkCertificateTime(cert *Certificate, now time.Time) error {
	if now.Before(cert.NotBefore) {
		return invalidError(cert, Expired, fmt.Sprintf("certificate is not valid before %s", cert.NotBefore))
	}
	if now.After(cert.NotAfter) {
		return invalidError(cert, Expired, fmt.Sprintf("certificate expired at %s", cert.NotAfter))
	}
	if len(cert.UnhandledCriticalExtensions) != 0 {
		return unsupportedCriticalError(cert)
	}
	return nil
}

func chainPermitsUsage(chain []*Certificate, usages []ExtKeyUsage) bool {
	if len(usages) == 0 {
		usages = []ExtKeyUsage{ExtKeyUsageServerAuth}
	}
	for _, requested := range usages {
		if requested == ExtKeyUsageAny {
			return true
		}
	}

	remaining := append([]ExtKeyUsage(nil), usages...)
	const invalidUsage ExtKeyUsage = -1
	for i := len(chain) - 1; i >= 0; i-- {
		cert := chain[i]
		if len(cert.ExtKeyUsage) == 0 && len(cert.UnknownExtKeyUsage) == 0 {
			continue
		}
		anyUsage := false
		for _, available := range cert.ExtKeyUsage {
			if available == ExtKeyUsageAny {
				anyUsage = true
				break
			}
		}
		if anyUsage {
			continue
		}
		for usageIndex, requested := range remaining {
			if requested == invalidUsage {
				continue
			}
			permitted := false
			for _, available := range cert.ExtKeyUsage {
				if available == requested {
					permitted = true
					break
				}
			}
			if !permitted {
				remaining[usageIndex] = invalidUsage
			}
		}
	}
	for _, usage := range remaining {
		if usage != invalidUsage {
			return true
		}
	}
	return false
}

func dnsConstraintMatches(name, constraint string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	constraint = strings.TrimSuffix(strings.ToLower(constraint), ".")
	if name == "" || constraint == "" {
		return false
	}
	if constraint[0] == '.' {
		return strings.HasSuffix(name, constraint) && len(name) > len(constraint)
	}
	return name == constraint || strings.HasSuffix(name, "."+constraint)
}

func permittedDNS(name string, permitted, excluded []string) bool {
	for _, constraint := range excluded {
		if dnsConstraintMatches(name, constraint) {
			return false
		}
	}
	if len(permitted) == 0 {
		return true
	}
	for _, constraint := range permitted {
		if dnsConstraintMatches(name, constraint) {
			return true
		}
	}
	return false
}

func emailConstraintMatches(address, constraint string) bool {
	at := strings.LastIndexByte(address, '@')
	if at < 0 {
		return false
	}
	if strings.Contains(constraint, "@") {
		return strings.EqualFold(address, constraint)
	}
	return dnsConstraintMatches(address[at+1:], constraint)
}

func permittedEmail(address string, permitted, excluded []string) bool {
	for _, constraint := range excluded {
		if emailConstraintMatches(address, constraint) {
			return false
		}
	}
	if len(permitted) == 0 {
		return true
	}
	for _, constraint := range permitted {
		if emailConstraintMatches(address, constraint) {
			return true
		}
	}
	return false
}

func permittedIP(ip net.IP, permitted, excluded []*net.IPNet) bool {
	for _, network := range excluded {
		if network.Contains(ip) {
			return false
		}
	}
	if len(permitted) == 0 {
		return true
	}
	for _, network := range permitted {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func permittedURI(uri *url.URL, permitted, excluded []string) bool {
	if uri == nil || uri.Hostname() == "" || net.ParseIP(uri.Hostname()) != nil {
		return false
	}
	return permittedDNS(uri.Hostname(), permitted, excluded)
}

func hasNameConstraints(cert *Certificate) bool {
	return len(cert.PermittedDNSDomains) != 0 || len(cert.ExcludedDNSDomains) != 0 ||
		len(cert.PermittedIPRanges) != 0 || len(cert.ExcludedIPRanges) != 0 ||
		len(cert.PermittedEmailAddresses) != 0 || len(cert.ExcludedEmailAddresses) != 0 ||
		len(cert.PermittedURIDomains) != 0 || len(cert.ExcludedURIDomains) != 0
}

func checkNameConstraints(chain []*Certificate, opts VerifyOptions) error {
	if len(chain) < 2 {
		return nil
	}
	maxComparisons := opts.MaxConstraintComparisions
	if maxComparisons == 0 {
		maxComparisons = 250000
	}
	comparisons := 0
	addComparisons := func(ca *Certificate, count int) error {
		comparisons += count
		if comparisons > maxComparisons {
			return invalidError(ca, TooManyConstraints, "name constraint comparison limit exceeded")
		}
		return nil
	}

	// A CA constrains every certificate below it, including intermediates, not
	// only the leaf. chain is ordered leaf-to-root.
	for caIndex := 1; caIndex < len(chain); caIndex++ {
		ca := chain[caIndex]
		if !hasNameConstraints(ca) {
			continue
		}
		for childIndex := 0; childIndex < caIndex; childIndex++ {
			child := chain[childIndex]
			for _, name := range child.DNSNames {
				if err := addComparisons(ca, len(ca.PermittedDNSDomains)+len(ca.ExcludedDNSDomains)); err != nil {
					return err
				}
				if !permittedDNS(name, ca.PermittedDNSDomains, ca.ExcludedDNSDomains) {
					return invalidError(child, CANotAuthorizedForThisName, "DNS name constrained by CA")
				}
			}
			for _, address := range child.EmailAddresses {
				if err := addComparisons(ca, len(ca.PermittedEmailAddresses)+len(ca.ExcludedEmailAddresses)); err != nil {
					return err
				}
				if !permittedEmail(address, ca.PermittedEmailAddresses, ca.ExcludedEmailAddresses) {
					return invalidError(child, CANotAuthorizedForThisName, "email address constrained by CA")
				}
			}
			for _, ip := range child.IPAddresses {
				if err := addComparisons(ca, len(ca.PermittedIPRanges)+len(ca.ExcludedIPRanges)); err != nil {
					return err
				}
				if !permittedIP(ip, ca.PermittedIPRanges, ca.ExcludedIPRanges) {
					return invalidError(child, CANotAuthorizedForThisName, "IP address constrained by CA")
				}
			}
			for _, uri := range child.URIs {
				if err := addComparisons(ca, len(ca.PermittedURIDomains)+len(ca.ExcludedURIDomains)); err != nil {
					return err
				}
				if !permittedURI(uri, ca.PermittedURIDomains, ca.ExcludedURIDomains) {
					return invalidError(child, CANotAuthorizedForThisName, "URI constrained by CA")
				}
			}
			if ca.PermittedDNSDomainsCritical && len(child.DNSNames) == 0 &&
				len(child.EmailAddresses) == 0 && len(child.IPAddresses) == 0 && len(child.URIs) == 0 {
				return invalidError(child, NameConstraintsWithoutSANs, "critical name constraints require a SAN")
			}
		}
	}
	return nil
}

func validateBuiltChain(chain []*Certificate, opts VerifyOptions, now time.Time) error {
	for _, cert := range chain {
		if err := checkCertificateTime(cert, now); err != nil {
			return err
		}
	}
	if opts.DNSName != "" {
		if err := chain[0].VerifyHostname(opts.DNSName); err != nil {
			return err
		}
	}
	if !chainPermitsUsage(chain, opts.KeyUsages) {
		return invalidError(chain[0], IncompatibleUsage, "certificate is not valid for the requested usage")
	}
	for i := 1; i < len(chain); i++ {
		ca := chain[i]
		if i < len(chain)-1 || !ca.Equal(chain[0]) {
			if ca.Version == 3 && (!ca.BasicConstraintsValid || !ca.IsCA) {
				return invalidError(ca, NotAuthorizedToSign, "certificate is not a CA")
			}
			if ca.KeyUsage != 0 && ca.KeyUsage&KeyUsageCertSign == 0 {
				return invalidError(ca, NotAuthorizedToSign, "certificate lacks keyCertSign usage")
			}
		}
		if ca.BasicConstraintsValid && (ca.MaxPathLen > 0 || ca.MaxPathLenZero) {
			intermediatesBelow := i - 1
			if intermediatesBelow > ca.MaxPathLen {
				return invalidError(ca, TooManyIntermediates, "path length constraint exceeded")
			}
		}
	}
	return checkNameConstraints(chain, opts)
}

func buildGOSTChains(leaf *Certificate, opts VerifyOptions, now time.Time) ([][]*Certificate, error) {
	if opts.Roots == nil {
		return nil, errNoRoots
	}
	for _, root := range opts.Roots.certs {
		if leaf.Equal(root) {
			chain := []*Certificate{leaf}
			if err := validateBuiltChain(chain, opts, now); err != nil {
				return nil, err
			}
			return [][]*Certificate{chain}, nil
		}
	}

	var chains [][]*Certificate
	var firstErr error
	signatureChecks := 0
	checkSignature := func(child, parent *Certificate) error {
		signatureChecks++
		if signatureChecks > maxChainSignatureChecks {
			return errSignatureLimit
		}
		return child.CheckSignatureFrom(parent)
	}
	var walk func([]*Certificate)
	walk = func(chain []*Certificate) {
		if errors.Is(firstErr, errSignatureLimit) {
			return
		}
		if len(chain) > 100 {
			if firstErr == nil {
				firstErr = invalidError(chain[0], TooManyIntermediates, "certificate chain too long")
			}
			return
		}
		current := chain[len(chain)-1]
		for _, root := range candidatesBySubject(opts.Roots, current.RawIssuer) {
			if certInChain(chain, root) {
				continue
			}
			if err := checkSignature(current, root); err != nil {
				if errors.Is(err, errSignatureLimit) {
					firstErr = err
					return
				}
				continue
			}
			candidate := append(append([]*Certificate(nil), chain...), root)
			if err := validateBuiltChain(candidate, opts, now); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			chains = append(chains, candidate)
		}
		for _, parent := range candidatesBySubject(opts.Intermediates, current.RawIssuer) {
			if certInChain(chain, parent) {
				continue
			}
			if err := checkSignature(current, parent); err != nil {
				if errors.Is(err, errSignatureLimit) {
					firstErr = err
					return
				}
				continue
			}
			walk(append(append([]*Certificate(nil), chain...), parent))
			if errors.Is(firstErr, errSignatureLimit) {
				return
			}
		}
	}
	walk([]*Certificate{leaf})
	if len(chains) != 0 {
		return chains, nil
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return nil, unknownAuthority(leaf)
}

// Verify builds and validates certificate chains. Ordinary certificates use
// crypto/x509's platform verifier; chains containing GOST algorithms use the
// verifier above with explicitly configured GOST roots.
func (c *Certificate) Verify(opts VerifyOptions) ([][]*Certificate, error) {
	if !c.isGOSTChainCertificate() {
		chains, err := asStandard(c).Verify(opts.standardOptions())
		if err != nil {
			return nil, err
		}
		return fromStandardChains(chains), nil
	}
	now := opts.CurrentTime
	if now.IsZero() {
		now = time.Now()
	}
	return buildGOSTChains(c, opts, now)
}
