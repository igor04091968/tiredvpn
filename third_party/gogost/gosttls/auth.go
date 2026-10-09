// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gosttls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"hash"
	"io"
	"slices"

	"gitverse.ru/uzer_007/gogost/v3/gost3410"
	"gitverse.ru/uzer_007/gogost/v3/gost34112012256"
	"gitverse.ru/uzer_007/gogost/v3/gost34112012512"
)

// crypto.Hash is intentionally not globally extended. These private sentinel
// values flow only through the TLS signing code, where GOST hashing is handled
// explicitly before invoking crypto.Signer.
const (
	gostHash256 crypto.Hash = 100
	gostHash512 crypto.Hash = 101
)

// verifyHandshakeSignature verifies a signature against unhashed handshake contents.
func verifyHandshakeSignature(sigType uint8, pubkey crypto.PublicKey, hashFunc crypto.Hash, signed, sig []byte) error {
	if sigType == signatureGOST {
		var err error
		signed, err = gostHandshakeDigest(hashFunc, signed)
		if err != nil {
			return err
		}
	} else if hashFunc != directSigning {
		if !hashFunc.Available() {
			return fmt.Errorf("hash function unavailable: %v", hashFunc)
		}
		h := hashFunc.New()
		h.Write(signed)
		signed = h.Sum(nil)
	}
	switch sigType {
	case signatureECDSA:
		pubKey, ok := pubkey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("expected an ECDSA public key, got %T", pubkey)
		}
		if !ecdsa.VerifyASN1(pubKey, signed, sig) {
			return errors.New("ECDSA verification failure")
		}
	case signatureEd25519:
		pubKey, ok := pubkey.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("expected an Ed25519 public key, got %T", pubkey)
		}
		if !ed25519.Verify(pubKey, signed, sig) {
			return errors.New("Ed25519 verification failure")
		}
	case signatureMLDSA:
		pubKey, ok := pubkey.(*mldsa.PublicKey)
		if !ok {
			return fmt.Errorf("expected an ML-DSA public key, got %T", pubkey)
		}
		if err := mldsa.Verify(pubKey, signed, sig, nil); err != nil {
			return fmt.Errorf("ML-DSA verification failure: %w", err)
		}
	case signaturePKCS1v15:
		pubKey, ok := pubkey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("expected an RSA public key, got %T", pubkey)
		}
		if err := rsa.VerifyPKCS1v15(pubKey, hashFunc, signed, sig); err != nil {
			return err
		}
	case signatureRSAPSS:
		pubKey, ok := pubkey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("expected an RSA public key, got %T", pubkey)
		}
		signOpts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
		if err := rsa.VerifyPSS(pubKey, hashFunc, signed, sig, signOpts); err != nil {
			return err
		}
	case signatureGOST:
		pubKey, ok := pubkey.(*gost3410.PublicKey)
		if !ok {
			return fmt.Errorf("expected a GOST public key, got %T", pubkey)
		}
		valid, err := (gost3410.PublicKeyReverseDigestAndSignature{Pub: pubKey}).VerifyDigest(signed, sig)
		if err != nil {
			return err
		}
		if !valid {
			return errors.New("GOST verification failure")
		}
	default:
		return errors.New("internal error: unknown signature type")
	}
	return nil
}

// verifyLegacyHandshakeSignature verifies a TLS 1.0 and 1.1 signature against
// pre-hashed handshake contents.
func verifyLegacyHandshakeSignature(sigType uint8, pubkey crypto.PublicKey, hashFunc crypto.Hash, hashed, sig []byte) error {
	switch sigType {
	case signatureECDSA:
		pubKey, ok := pubkey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("expected an ECDSA public key, got %T", pubkey)
		}
		if !ecdsa.VerifyASN1(pubKey, hashed, sig) {
			return errors.New("ECDSA verification failure")
		}
	case signaturePKCS1v15:
		pubKey, ok := pubkey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("expected an RSA public key, got %T", pubkey)
		}
		if err := rsa.VerifyPKCS1v15(pubKey, hashFunc, hashed, sig); err != nil {
			return err
		}
	default:
		return errors.New("internal error: unknown signature type")
	}
	return nil
}

const (
	serverSignatureContext = "TLS 1.3, server CertificateVerify\x00"
	clientSignatureContext = "TLS 1.3, client CertificateVerify\x00"
)

var signaturePadding = []byte{
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
}

// signedMessage returns the unhashed message to be signed by certificate keys
// in TLS 1.3. See RFC 8446, Section 4.4.3.
func signedMessage(context string, transcript hash.Hash) []byte {
	const maxSize = 64 /* signaturePadding */ + len(serverSignatureContext) + 512/8 /* SHA-512 */
	b := bytes.NewBuffer(make([]byte, 0, maxSize))
	b.Write(signaturePadding)
	io.WriteString(b, context)
	b.Write(transcript.Sum(nil))
	return b.Bytes()
}

func gostHandshakeDigest(hashFunc crypto.Hash, message []byte) ([]byte, error) {
	var h hash.Hash
	switch hashFunc {
	case gostHash256:
		h = gost34112012256.New()
	case gostHash512:
		h = gost34112012512.New()
	default:
		return nil, errors.New("tls: internal error: invalid GOST signature hash")
	}
	_, _ = h.Write(message)
	return h.Sum(nil), nil
}

// signHandshakeMessage preserves Go 1.27 crypto.MessageSigner support for
// standard algorithms while adapting the private GOST hash identifiers, which
// intentionally cannot be registered in crypto.Hash.
func signHandshakeMessage(signer crypto.Signer, rand io.Reader, message []byte, sigType uint8, opts crypto.SignerOpts) ([]byte, error) {
	if sigType != signatureGOST {
		return crypto.SignMessage(signer, rand, message, opts)
	}
	digest, err := gostHandshakeDigest(opts.HashFunc(), message)
	if err != nil {
		return nil, err
	}
	return signer.Sign(rand, digest, opts)
}

// typeAndHashFromSignatureScheme returns the corresponding signature type and
// crypto.Hash for a given TLS SignatureScheme.
func typeAndHashFromSignatureScheme(signatureAlgorithm SignatureScheme) (sigType uint8, hash crypto.Hash, err error) {
	switch signatureAlgorithm {
	case PKCS1WithSHA1, PKCS1WithSHA256, PKCS1WithSHA384, PKCS1WithSHA512:
		sigType = signaturePKCS1v15
	case PSSWithSHA256, PSSWithSHA384, PSSWithSHA512:
		sigType = signatureRSAPSS
	case ECDSAWithSHA1, ECDSAWithP256AndSHA256, ECDSAWithP384AndSHA384, ECDSAWithP521AndSHA512:
		sigType = signatureECDSA
	case Ed25519:
		sigType = signatureEd25519
	case MLDSA44, MLDSA65, MLDSA87:
		sigType = signatureMLDSA
	case GOSTR34102012256A, GOSTR34102012256B, GOSTR34102012256C,
		GOSTR34102012256D, GOSTR34102012512A, GOSTR34102012512B,
		GOSTR34102012512C:
		sigType = signatureGOST
	default:
		return 0, 0, fmt.Errorf("unsupported signature algorithm: %v", signatureAlgorithm)
	}
	switch signatureAlgorithm {
	case PKCS1WithSHA1, ECDSAWithSHA1:
		hash = crypto.SHA1
	case PKCS1WithSHA256, PSSWithSHA256, ECDSAWithP256AndSHA256:
		hash = crypto.SHA256
	case PKCS1WithSHA384, PSSWithSHA384, ECDSAWithP384AndSHA384:
		hash = crypto.SHA384
	case PKCS1WithSHA512, PSSWithSHA512, ECDSAWithP521AndSHA512:
		hash = crypto.SHA512
	case Ed25519, MLDSA44, MLDSA65, MLDSA87:
		hash = directSigning
	case GOSTR34102012256A, GOSTR34102012256B, GOSTR34102012256C, GOSTR34102012256D:
		hash = gostHash256
	case GOSTR34102012512A, GOSTR34102012512B, GOSTR34102012512C:
		hash = gostHash512
	default:
		return 0, 0, fmt.Errorf("unsupported signature algorithm: %v", signatureAlgorithm)
	}
	return sigType, hash, nil
}

// legacyTypeAndHashFromPublicKey returns the fixed signature type and crypto.Hash for
// a given public key used with TLS 1.0 and 1.1, before the introduction of
// signature algorithm negotiation.
func legacyTypeAndHashFromPublicKey(pub crypto.PublicKey) (sigType uint8, hash crypto.Hash, err error) {
	switch pub.(type) {
	case *rsa.PublicKey:
		return signaturePKCS1v15, crypto.MD5SHA1, nil
	case *ecdsa.PublicKey:
		return signatureECDSA, crypto.SHA1, nil
	case ed25519.PublicKey:
		// RFC 8422 specifies support for Ed25519 in TLS 1.0 and 1.1,
		// but it requires holding on to a handshake transcript to do a
		// full signature, and not even OpenSSL bothers with the
		// complexity, so we can't even test it properly.
		return 0, 0, fmt.Errorf("tls: Ed25519 public keys are not supported before TLS 1.2")
	case *mldsa.PublicKey:
		return 0, 0, fmt.Errorf("tls: ML-DSA public keys are not supported before TLS 1.3")
	default:
		return 0, 0, fmt.Errorf("tls: unsupported public key: %T", pub)
	}
}

var rsaSignatureSchemes = []struct {
	scheme          SignatureScheme
	minModulusBytes int
}{
	// RSA-PSS is used with PSSSaltLengthEqualsHash, and requires
	//    emLen >= hLen + sLen + 2
	{PSSWithSHA256, crypto.SHA256.Size()*2 + 2},
	{PSSWithSHA384, crypto.SHA384.Size()*2 + 2},
	{PSSWithSHA512, crypto.SHA512.Size()*2 + 2},
	// PKCS #1 v1.5 uses prefixes from hashPrefixes in crypto/rsa, and requires
	//    emLen >= len(prefix) + hLen + 11
	{PKCS1WithSHA256, 19 + crypto.SHA256.Size() + 11},
	{PKCS1WithSHA384, 19 + crypto.SHA384.Size() + 11},
	{PKCS1WithSHA512, 19 + crypto.SHA512.Size() + 11},
	{PKCS1WithSHA1, 15 + crypto.SHA1.Size() + 11},
}

func signatureSchemesForPublicKey(version uint16, pub crypto.PublicKey) []SignatureScheme {
	switch pub := pub.(type) {
	case *ecdsa.PublicKey:
		if version < VersionTLS13 {
			// In TLS 1.2 and earlier, ECDSA algorithms are not
			// constrained to a single curve.
			return []SignatureScheme{
				ECDSAWithP256AndSHA256,
				ECDSAWithP384AndSHA384,
				ECDSAWithP521AndSHA512,
				ECDSAWithSHA1,
			}
		}
		switch pub.Curve {
		case elliptic.P256():
			return []SignatureScheme{ECDSAWithP256AndSHA256}
		case elliptic.P384():
			return []SignatureScheme{ECDSAWithP384AndSHA384}
		case elliptic.P521():
			return []SignatureScheme{ECDSAWithP521AndSHA512}
		default:
			return nil
		}
	case *rsa.PublicKey:
		size := pub.Size()
		sigAlgs := make([]SignatureScheme, 0, len(rsaSignatureSchemes))
		for _, candidate := range rsaSignatureSchemes {
			if size >= candidate.minModulusBytes {
				sigAlgs = append(sigAlgs, candidate.scheme)
			}
		}
		return sigAlgs
	case ed25519.PublicKey:
		return []SignatureScheme{Ed25519}
	case *mldsa.PublicKey:
		switch pub.Parameters() {
		case mldsa.MLDSA44():
			return []SignatureScheme{MLDSA44}
		case mldsa.MLDSA65():
			return []SignatureScheme{MLDSA65}
		case mldsa.MLDSA87():
			return []SignatureScheme{MLDSA87}
		default:
			panic("tls: internal error: unknown ML-DSA parameter set: " + pub.Parameters().String())
		}
	case *gost3410.PublicKey:
		switch pub.C.Name {
		case "id-tc26-gost-3410-12-256-paramSetA", "id-tc26-gost-3410-2012-256-paramSetA":
			return []SignatureScheme{GOSTR34102012256A}
		case "id-tc26-gost-3410-12-256-paramSetB", "id-tc26-gost-3410-2012-256-paramSetB":
			return []SignatureScheme{GOSTR34102012256B}
		case "id-tc26-gost-3410-12-256-paramSetC", "id-tc26-gost-3410-2012-256-paramSetC":
			return []SignatureScheme{GOSTR34102012256C}
		case "id-tc26-gost-3410-12-256-paramSetD", "id-tc26-gost-3410-2012-256-paramSetD":
			return []SignatureScheme{GOSTR34102012256D}
		case "id-tc26-gost-3410-12-512-paramSetA", "id-tc26-gost-3410-2012-512-paramSetA":
			return []SignatureScheme{GOSTR34102012512A}
		case "id-tc26-gost-3410-12-512-paramSetB", "id-tc26-gost-3410-2012-512-paramSetB":
			return []SignatureScheme{GOSTR34102012512B}
		case "id-tc26-gost-3410-12-512-paramSetC", "id-tc26-gost-3410-2012-512-paramSetC":
			return []SignatureScheme{GOSTR34102012512C}
		default:
			return nil
		}
	default:
		return nil
	}
}

// selectSignatureScheme picks a SignatureScheme from the peer's preference list
// that works with the selected certificate. It's only called for protocol
// versions that support signature algorithms, so TLS 1.2 and 1.3.
func selectSignatureScheme(vers uint16, c *Certificate, peerAlgs []SignatureScheme) (SignatureScheme, error) {
	priv, ok := c.PrivateKey.(crypto.Signer)
	if !ok {
		return 0, unsupportedCertificateError(c)
	}
	supportedAlgs := signatureSchemesForPublicKey(vers, priv.Public())
	if c.SupportedSignatureAlgorithms != nil {
		supportedAlgs = slices.DeleteFunc(supportedAlgs, func(sigAlg SignatureScheme) bool {
			return !isSupportedSignatureAlgorithm(sigAlg, c.SupportedSignatureAlgorithms)
		})
	}
	supportedAlgs = slices.DeleteFunc(supportedAlgs, func(sigAlg SignatureScheme) bool {
		return isDisabledSignatureAlgorithm(vers, sigAlg, false)
	})
	if len(supportedAlgs) == 0 {
		return 0, unsupportedCertificateError(c)
	}
	if len(peerAlgs) == 0 && vers == VersionTLS12 {
		// For TLS 1.2, if the client didn't send signature_algorithms then we
		// can assume that it supports SHA1. See RFC 5246, Section 7.4.1.4.1.
		// RFC 9155 made signature_algorithms mandatory in TLS 1.2. Preserve the
		// legacy behavior only when explicitly enabled.
		if tlssha1.Value() != "1" {
			return 0, errors.New("tls: missing signature_algorithms from TLS 1.2 peer")
		}
		peerAlgs = []SignatureScheme{PKCS1WithSHA1, ECDSAWithSHA1}
	}
	// Pick signature scheme in the peer's preference order, as our
	// preference order is not configurable.
	for _, preferredAlg := range peerAlgs {
		if isSupportedSignatureAlgorithm(preferredAlg, supportedAlgs) {
			return preferredAlg, nil
		}
	}
	return 0, errors.New("tls: peer doesn't support any of the certificate's signature algorithms")
}

// unsupportedCertificateError returns a helpful error for certificates with
// an unsupported private key.
func unsupportedCertificateError(cert *Certificate) error {
	switch cert.PrivateKey.(type) {
	case rsa.PrivateKey, ecdsa.PrivateKey:
		return fmt.Errorf("tls: unsupported certificate: private key is %T, expected *%T",
			cert.PrivateKey, cert.PrivateKey)
	case *ed25519.PrivateKey:
		return fmt.Errorf("tls: unsupported certificate: private key is *ed25519.PrivateKey, expected ed25519.PrivateKey")
	}

	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("tls: certificate private key (%T) does not implement crypto.Signer",
			cert.PrivateKey)
	}

	switch pub := signer.Public().(type) {
	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P256():
		case elliptic.P384():
		case elliptic.P521():
		default:
			return fmt.Errorf("tls: unsupported certificate curve (%s)", pub.Curve.Params().Name)
		}
	case *rsa.PublicKey:
		return fmt.Errorf("tls: certificate RSA key size too small for supported signature algorithms")
	case ed25519.PublicKey:
	case *mldsa.PublicKey:
		return errors.New("tls: ML-DSA certificates require TLS 1.3")
	case *gost3410.PublicKey:
	default:
		return fmt.Errorf("tls: unsupported certificate key (%T)", pub)
	}

	if cert.SupportedSignatureAlgorithms != nil {
		return fmt.Errorf("tls: peer doesn't support the certificate custom signature algorithms")
	}

	return fmt.Errorf("tls: internal error: unsupported key (%T)", cert.PrivateKey)
}
