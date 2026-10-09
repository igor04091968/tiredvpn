// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gosttls

import (
	"crypto"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/mlkem"
	"errors"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

// This file contains the functions necessary to compute the TLS 1.3 key
// schedule. See RFC 8446, Section 7.

const (
	resumptionBinderLabel         = "res binder"
	clientEarlyTrafficLabel       = "c e traffic"
	clientHandshakeTrafficLabel   = "c hs traffic"
	serverHandshakeTrafficLabel   = "s hs traffic"
	clientApplicationTrafficLabel = "c ap traffic"
	serverApplicationTrafficLabel = "s ap traffic"
	exporterLabel                 = "exp master"
	resumptionLabel               = "res master"
	trafficUpdateLabel            = "traffic upd"
)

// expandLabel implements HKDF-Expand-Label from RFC 8446, Section 7.1.
func (c *cipherSuiteTLS13) expandLabel(secret []byte, label string, context []byte, length int) []byte {
	if c.hash == hashGOST256 {
		return gostExpandLabel(secret, label, context, length)
	}
	var hkdfLabel cryptobyte.Builder
	hkdfLabel.AddUint16(uint16(length))
	hkdfLabel.AddUint8LengthPrefixed(func(builder *cryptobyte.Builder) {
		builder.AddBytes([]byte("tls13 "))
		builder.AddBytes([]byte(label))
	})
	hkdfLabel.AddUint8LengthPrefixed(func(builder *cryptobyte.Builder) {
		builder.AddBytes(context)
	})
	encoded, err := hkdfLabel.Bytes()
	if err != nil {
		panic(fmt.Errorf("tls: failed to construct HKDF label: %w", err))
	}
	out, err := hkdf.Expand(c.hash.New, secret, string(encoded), length)
	if err != nil {
		panic("tls: HKDF-Expand-Label invocation failed unexpectedly")
	}
	return out
}

func (c *cipherSuiteTLS13) deriveSecret(secret []byte, label string, transcript hash.Hash) []byte {
	if transcript == nil {
		transcript = c.hash.New()
	}
	return c.expandLabel(secret, label, transcript.Sum(nil), c.hash.Size())
}

func (c *cipherSuiteTLS13) extract(newSecret, currentSecret []byte) []byte {
	if c.hash == hashGOST256 {
		if newSecret == nil {
			var zeroSecret [gostHKDFHashSize]byte
			return gostHKDFExtract(zeroSecret[:], currentSecret)
		}
		return gostHKDFExtract(newSecret, currentSecret)
	}
	if newSecret == nil {
		newSecret = make([]byte, c.hash.Size())
	}
	out, err := hkdf.Extract(c.hash.New, newSecret, currentSecret)
	if err != nil {
		panic("tls: HKDF-Extract invocation failed unexpectedly")
	}
	return out
}

// nextTrafficSecret generates the next traffic secret, given the current one,
// according to RFC 8446, Section 7.2.
func (c *cipherSuiteTLS13) nextTrafficSecret(trafficSecret []byte) []byte {
	return c.expandLabel(trafficSecret, trafficUpdateLabel, nil, c.hash.Size())
}

// trafficKey generates traffic keys according to RFC 8446, Section 7.3.
func (c *cipherSuiteTLS13) trafficKey(trafficSecret []byte) (key, iv []byte) {
	key = c.expandLabel(trafficSecret, "key", nil, c.keyLen)
	iv = c.expandLabel(trafficSecret, "iv", nil, c.ivLen)
	return
}

// finishedHash generates the Finished verify_data or PskBinderEntry according
// to RFC 8446, Section 4.4.4. See sections 4.4 and 4.2.11.2 for the baseKey
// selection.
func (c *cipherSuiteTLS13) finishedHash(baseKey []byte, transcript hash.Hash) []byte {
	if c.hash == hashGOST256 {
		transcriptDigest := gostHashSum(transcript)
		verifyData := gostFinishedHash(baseKey, transcriptDigest[:])
		clear(transcriptDigest[:])
		return verifyData
	}
	finishedKey := c.expandLabel(baseKey, "finished", nil, c.hash.Size())
	verifyData := hmac.New(c.hash.New, finishedKey)
	verifyData.Write(transcript.Sum(nil))
	return verifyData.Sum(nil)
}

// exportKeyingMaterial implements RFC5705 exporters for TLS 1.3 according to
// RFC 8446, Section 7.5.
func (c *cipherSuiteTLS13) exportKeyingMaterial(masterSecret []byte, transcript hash.Hash) func(string, []byte, int) ([]byte, error) {
	expMasterSecret := c.deriveSecret(masterSecret, exporterLabel, transcript)
	return func(label string, context []byte, length int) ([]byte, error) {
		secret := c.deriveSecret(expMasterSecret, label, nil)
		if c.hash == hashGOST256 {
			digest := gostHashSumBytes(context)
			out := c.expandLabel(secret, "exporter", digest[:], length)
			clear(secret)
			clear(digest[:])
			return out, nil
		}
		digest := c.hash.New()
		digest.Write(context)
		return c.expandLabel(secret, "exporter", digest.Sum(nil), length), nil
	}
}

// generateECDHEKey returns a PrivateKey that implements Diffie-Hellman
// according to RFC 8446, Section 4.2.8.2. It is kept separate from the TLS 1.3
// keyExchange abstraction because TLS 1.2 still uses the ECDHE helpers below.
func generateECDHEKey(rand io.Reader, curveID CurveID) (*ecdh.PrivateKey, error) {
	curve, ok := curveForCurveID(curveID)
	if !ok {
		return nil, errors.New("tls: internal error: unsupported curve")
	}
	return curve.GenerateKey(rand)
}

func curveForCurveID(id CurveID) (ecdh.Curve, bool) {
	switch id {
	case X25519:
		return ecdh.X25519(), true
	case CurveP256:
		return ecdh.P256(), true
	case CurveP384:
		return ecdh.P384(), true
	case CurveP521:
		return ecdh.P521(), true
	default:
		return nil, false
	}
}

func curveIDForCurve(curve ecdh.Curve) (CurveID, bool) {
	switch curve {
	case ecdh.X25519():
		return X25519, true
	case ecdh.P256():
		return CurveP256, true
	case ecdh.P384():
		return CurveP384, true
	case ecdh.P521():
		return CurveP521, true
	default:
		return 0, false
	}
}

type keySharePrivateKeys struct {
	ecdhe *ecdh.PrivateKey
	mlkem crypto.Decapsulator
	gost  tls13KeyShare

	// byGroup is populated when a mixed default ClientHello carries both a
	// GOST key share and an upstream PQ/ECDHE fallback.
	byGroup map[CurveID]*keySharePrivateKeys
}

// A keyExchange implements a TLS 1.3 KEM.
type keyExchange interface {
	// keyShares generates one or two key shares.
	//
	// The first one will match the id, the second (if present) reuses the
	// traditional component of the requested hybrid, as allowed by
	// draft-ietf-tls-hybrid-design-09, Section 3.2.
	keyShares(rand io.Reader) (*keySharePrivateKeys, []keyShare, error)

	// serverSharedSecret computes the shared secret and the server's key share.
	serverSharedSecret(rand io.Reader, clientKeyShare []byte) ([]byte, keyShare, error)

	// clientSharedSecret computes the shared secret given the server's key
	// share and the keys generated by keyShares.
	clientSharedSecret(priv *keySharePrivateKeys, serverKeyShare []byte) ([]byte, error)
}

func keyExchangeForCurveID(id CurveID) (keyExchange, error) {
	if isGOSTCurve(id) {
		return &gostKeyExchange{id: id}, nil
	}
	mlkemGenerateKey768 := func() (crypto.Decapsulator, error) {
		return mlkem.GenerateKey768()
	}
	mlkemGenerateKey1024 := func() (crypto.Decapsulator, error) {
		return mlkem.GenerateKey1024()
	}
	mlkemNewPublicKey768 := func(b []byte) (crypto.Encapsulator, error) {
		return mlkem.NewEncapsulationKey768(b)
	}
	mlkemNewPublicKey1024 := func(b []byte) (crypto.Encapsulator, error) {
		return mlkem.NewEncapsulationKey1024(b)
	}
	switch id {
	case X25519:
		return &ecdhKeyExchange{id, ecdh.X25519()}, nil
	case CurveP256:
		return &ecdhKeyExchange{id, ecdh.P256()}, nil
	case CurveP384:
		return &ecdhKeyExchange{id, ecdh.P384()}, nil
	case CurveP521:
		return &ecdhKeyExchange{id, ecdh.P521()}, nil
	case X25519MLKEM768:
		return &hybridKeyExchange{id, ecdhKeyExchange{X25519, ecdh.X25519()},
			32, mlkem.EncapsulationKeySize768, mlkem.CiphertextSize768,
			mlkemGenerateKey768, mlkemNewPublicKey768}, nil
	case SecP256r1MLKEM768:
		return &hybridKeyExchange{id, ecdhKeyExchange{CurveP256, ecdh.P256()},
			65, mlkem.EncapsulationKeySize768, mlkem.CiphertextSize768,
			mlkemGenerateKey768, mlkemNewPublicKey768}, nil
	case SecP384r1MLKEM1024:
		return &hybridKeyExchange{id, ecdhKeyExchange{CurveP384, ecdh.P384()},
			97, mlkem.EncapsulationKeySize1024, mlkem.CiphertextSize1024,
			mlkemGenerateKey1024, mlkemNewPublicKey1024}, nil
	case MLKEM1024:
		return &mlkem1024KeyExchange{}, nil
	default:
		return nil, errors.New("tls: unsupported key exchange")
	}
}

type mlkem1024KeyExchange struct{}

func (ke *mlkem1024KeyExchange) keyShares(_ io.Reader) (*keySharePrivateKeys, []keyShare, error) {
	priv, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, nil, err
	}
	return &keySharePrivateKeys{mlkem: priv}, []keyShare{{MLKEM1024, priv.EncapsulationKey().Bytes()}}, nil
}

func (ke *mlkem1024KeyExchange) serverSharedSecret(_ io.Reader, clientKeyShare []byte) ([]byte, keyShare, error) {
	peerKey, err := mlkem.NewEncapsulationKey1024(clientKeyShare)
	if err != nil {
		return nil, keyShare{}, err
	}
	sharedKey, keyShareData := peerKey.Encapsulate()
	return sharedKey, keyShare{MLKEM1024, keyShareData}, nil
}

func (ke *mlkem1024KeyExchange) clientSharedSecret(priv *keySharePrivateKeys, serverKeyShare []byte) ([]byte, error) {
	if selected := priv.byGroup[MLKEM1024]; selected != nil {
		priv = selected
	}
	if priv.mlkem == nil {
		return nil, errors.New("tls: missing ML-KEM private key for selected group")
	}
	return priv.mlkem.Decapsulate(serverKeyShare)
}

type ecdhKeyExchange struct {
	id    CurveID
	curve ecdh.Curve
}

func (ke *ecdhKeyExchange) keyShares(rand io.Reader) (*keySharePrivateKeys, []keyShare, error) {
	priv, err := ke.curve.GenerateKey(rand)
	if err != nil {
		return nil, nil, err
	}
	return &keySharePrivateKeys{ecdhe: priv}, []keyShare{{ke.id, priv.PublicKey().Bytes()}}, nil
}

func (ke *ecdhKeyExchange) serverSharedSecret(rand io.Reader, clientKeyShare []byte) ([]byte, keyShare, error) {
	key, err := ke.curve.GenerateKey(rand)
	if err != nil {
		return nil, keyShare{}, err
	}
	peerKey, err := ke.curve.NewPublicKey(clientKeyShare)
	if err != nil {
		return nil, keyShare{}, err
	}
	sharedKey, err := key.ECDH(peerKey)
	if err != nil {
		return nil, keyShare{}, err
	}
	return sharedKey, keyShare{ke.id, key.PublicKey().Bytes()}, nil
}

func (ke *ecdhKeyExchange) clientSharedSecret(priv *keySharePrivateKeys, serverKeyShare []byte) ([]byte, error) {
	if selected := priv.byGroup[ke.id]; selected != nil {
		priv = selected
	}
	if priv.ecdhe == nil {
		return nil, errors.New("tls: missing ECDHE private key for selected group")
	}
	peerKey, err := ke.curve.NewPublicKey(serverKeyShare)
	if err != nil {
		return nil, err
	}
	sharedKey, err := priv.ecdhe.ECDH(peerKey)
	if err != nil {
		return nil, err
	}
	return sharedKey, nil
}

type hybridKeyExchange struct {
	id   CurveID
	ecdh ecdhKeyExchange

	ecdhElementSize     int
	mlkemPublicKeySize  int
	mlkemCiphertextSize int

	mlkemGenerateKey  func() (crypto.Decapsulator, error)
	mlkemNewPublicKey func([]byte) (crypto.Encapsulator, error)
}

func (ke *hybridKeyExchange) keyShares(rand io.Reader) (*keySharePrivateKeys, []keyShare, error) {
	var (
		priv       *keySharePrivateKeys
		ecdhShares []keyShare
		err        error
	)
	priv, ecdhShares, err = ke.ecdh.keyShares(rand)
	if err != nil {
		return nil, nil, err
	}
	priv.mlkem, err = ke.mlkemGenerateKey()
	if err != nil {
		return nil, nil, err
	}
	var shareData []byte
	// For X25519MLKEM768, the ML-KEM-768 encapsulation key comes first.
	// For SecP256r1MLKEM768 and SecP384r1MLKEM1024, the ECDH share comes first.
	// See draft-ietf-tls-ecdhe-mlkem-02, Section 4.1.
	if ke.id == X25519MLKEM768 {
		shareData = append(priv.mlkem.Encapsulator().Bytes(), ecdhShares[0].data...)
	} else {
		shareData = append(ecdhShares[0].data, priv.mlkem.Encapsulator().Bytes()...)
	}
	return priv, []keyShare{{ke.id, shareData}, ecdhShares[0]}, nil
}

func (ke *hybridKeyExchange) serverSharedSecret(rand io.Reader, clientKeyShare []byte) ([]byte, keyShare, error) {
	if len(clientKeyShare) != ke.ecdhElementSize+ke.mlkemPublicKeySize {
		return nil, keyShare{}, errors.New("tls: invalid client key share length for hybrid key exchange")
	}
	var ecdhShareData, mlkemShareData []byte
	if ke.id == X25519MLKEM768 {
		mlkemShareData = clientKeyShare[:ke.mlkemPublicKeySize]
		ecdhShareData = clientKeyShare[ke.mlkemPublicKeySize:]
	} else {
		ecdhShareData = clientKeyShare[:ke.ecdhElementSize]
		mlkemShareData = clientKeyShare[ke.ecdhElementSize:]
	}
	var (
		ecdhSharedSecret []byte
		ks               keyShare
		err              error
	)
	ecdhSharedSecret, ks, err = ke.ecdh.serverSharedSecret(rand, ecdhShareData)
	if err != nil {
		return nil, keyShare{}, err
	}
	mlkemPeerKey, err := ke.mlkemNewPublicKey(mlkemShareData)
	if err != nil {
		return nil, keyShare{}, err
	}
	mlkemSharedSecret, mlkemKeyShare := mlkemPeerKey.Encapsulate()
	var sharedKey []byte
	if ke.id == X25519MLKEM768 {
		sharedKey = append(mlkemSharedSecret, ecdhSharedSecret...)
		ks.data = append(mlkemKeyShare, ks.data...)
	} else {
		sharedKey = append(ecdhSharedSecret, mlkemSharedSecret...)
		ks.data = append(ks.data, mlkemKeyShare...)
	}
	ks.group = ke.id
	return sharedKey, ks, nil
}

func (ke *hybridKeyExchange) clientSharedSecret(priv *keySharePrivateKeys, serverKeyShare []byte) ([]byte, error) {
	if selected := priv.byGroup[ke.id]; selected != nil {
		priv = selected
	}
	if priv.ecdhe == nil || priv.mlkem == nil {
		return nil, errors.New("tls: missing hybrid private key for selected group")
	}
	if len(serverKeyShare) != ke.ecdhElementSize+ke.mlkemCiphertextSize {
		return nil, errors.New("tls: invalid server key share length for hybrid key exchange")
	}
	var ecdhShareData, mlkemShareData []byte
	if ke.id == X25519MLKEM768 {
		mlkemShareData = serverKeyShare[:ke.mlkemCiphertextSize]
		ecdhShareData = serverKeyShare[ke.mlkemCiphertextSize:]
	} else {
		ecdhShareData = serverKeyShare[:ke.ecdhElementSize]
		mlkemShareData = serverKeyShare[ke.ecdhElementSize:]
	}
	var (
		ecdhSharedSecret []byte
		err              error
	)
	ecdhSharedSecret, err = ke.ecdh.clientSharedSecret(priv, ecdhShareData)
	if err != nil {
		return nil, err
	}
	mlkemSharedSecret, err := priv.mlkem.Decapsulate(mlkemShareData)
	if err != nil {
		return nil, err
	}
	var sharedKey []byte
	if ke.id == X25519MLKEM768 {
		sharedKey = append(mlkemSharedSecret, ecdhSharedSecret...)
	} else {
		sharedKey = append(ecdhSharedSecret, mlkemSharedSecret...)
	}
	return sharedKey, nil
}

type gostKeyExchange struct {
	id CurveID
}

func (ke *gostKeyExchange) keyShares(rand io.Reader) (*keySharePrivateKeys, []keyShare, error) {
	priv, err := generateTLS13KeyShare(rand, ke.id)
	if err != nil {
		return nil, nil, err
	}
	return &keySharePrivateKeys{gost: priv}, []keyShare{{group: ke.id, data: priv.PublicKeyBytes()}}, nil
}

func (ke *gostKeyExchange) serverSharedSecret(rand io.Reader, clientKeyShare []byte) ([]byte, keyShare, error) {
	priv, err := generateTLS13KeyShare(rand, ke.id)
	if err != nil {
		return nil, keyShare{}, err
	}
	shared, err := priv.ECDH(clientKeyShare)
	if err != nil {
		return nil, keyShare{}, err
	}
	return shared, keyShare{group: ke.id, data: priv.PublicKeyBytes()}, nil
}

func (ke *gostKeyExchange) clientSharedSecret(priv *keySharePrivateKeys, serverKeyShare []byte) ([]byte, error) {
	if selected := priv.byGroup[ke.id]; selected != nil {
		priv = selected
	}
	if priv.gost == nil || priv.gost.Group() != ke.id {
		return nil, errors.New("tls: missing GOST private key for selected group")
	}
	return priv.gost.ECDH(serverKeyShare)
}
