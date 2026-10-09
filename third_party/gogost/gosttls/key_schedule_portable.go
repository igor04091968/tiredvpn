// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gosttls

import (
	"crypto/hkdf"
	"encoding/binary"
	"hash"
)

// These small wrappers mirror the Go 1.27 TLS 1.3 key-schedule state types.
// crypto/tls uses an internal FIPS package for them; a standalone module must
// use the public crypto/hkdf implementation and makes no FIPS claim.

func expandLabelTLS13(hashFunc func() hash.Hash, secret []byte, label string, context []byte, length int) []byte {
	if len("tls13 ")+len(label) > 255 || len(context) > 255 {
		panic("gosttls: TLS 1.3 label or context too long")
	}
	encoded := make([]byte, 0, 2+1+len("tls13 ")+len(label)+1+len(context))
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(length))
	encoded = append(encoded, byte(len("tls13 ")+len(label)))
	encoded = append(encoded, "tls13 "...)
	encoded = append(encoded, label...)
	encoded = append(encoded, byte(len(context)))
	encoded = append(encoded, context...)
	out, err := hkdf.Expand(hashFunc, secret, string(encoded), length)
	if err != nil {
		panic("gosttls: HKDF-Expand-Label failed unexpectedly")
	}
	return out
}

func extractTLS13(hashFunc func() hash.Hash, newSecret, currentSecret []byte) []byte {
	if newSecret == nil {
		newSecret = make([]byte, hashFunc().Size())
	}
	out, err := hkdf.Extract(hashFunc, newSecret, currentSecret)
	if err != nil {
		panic("gosttls: HKDF-Extract failed unexpectedly")
	}
	return out
}

func deriveSecretTLS13(hashFunc func() hash.Hash, secret []byte, label string, transcript hash.Hash) []byte {
	if transcript == nil {
		transcript = hashFunc()
	}
	return expandLabelTLS13(hashFunc, secret, label, transcript.Sum(nil), transcript.Size())
}

func expandLabelForTLSHash(hashID tlsHash, secret []byte, label string, context []byte, length int) []byte {
	if hashID == hashGOST256 {
		return gostExpandLabel(secret, label, context, length)
	}
	return expandLabelTLS13(hashID.New, secret, label, context, length)
}

func extractForTLSHash(hashID tlsHash, newSecret, currentSecret []byte) []byte {
	if hashID == hashGOST256 {
		if newSecret == nil {
			var zeroSecret [gostHKDFHashSize]byte
			return gostHKDFExtract(zeroSecret[:], currentSecret)
		}
		return gostHKDFExtract(newSecret, currentSecret)
	}
	return extractTLS13(hashID.New, newSecret, currentSecret)
}

func deriveSecretForTLSHash(hashID tlsHash, secret []byte, label string, transcript hash.Hash) []byte {
	if transcript == nil {
		transcript = hashID.New()
	}
	if hashID == hashGOST256 {
		digest := gostHashSum(transcript)
		derived := gostExpandLabel(secret, label, digest[:], gostHKDFHashSize)
		clear(digest[:])
		return derived
	}
	digest := transcript.Sum(nil)
	derived := expandLabelForTLSHash(hashID, secret, label, digest, hashID.Size())
	clear(digest)
	return derived
}

type earlySecretTLS13 struct {
	secret []byte
	hash   tlsHash
}

func newEarlySecretTLS13(hashID tlsHash, psk []byte) *earlySecretTLS13 {
	return &earlySecretTLS13{secret: extractForTLSHash(hashID, psk, nil), hash: hashID}
}

func (s *earlySecretTLS13) resumptionBinderKey() []byte {
	return deriveSecretForTLSHash(s.hash, s.secret, resumptionBinderLabel, nil)
}

type handshakeSecretTLS13 struct {
	secret []byte
	hash   tlsHash
}

func (s *earlySecretTLS13) handshakeSecret(sharedSecret []byte) *handshakeSecretTLS13 {
	derived := deriveSecretForTLSHash(s.hash, s.secret, "derived", nil)
	secret := extractForTLSHash(s.hash, sharedSecret, derived)
	clear(derived)
	return &handshakeSecretTLS13{secret: secret, hash: s.hash}
}

func (s *handshakeSecretTLS13) clientTrafficSecret(transcript hash.Hash) []byte {
	return deriveSecretForTLSHash(s.hash, s.secret, clientHandshakeTrafficLabel, transcript)
}

func (s *handshakeSecretTLS13) serverTrafficSecret(transcript hash.Hash) []byte {
	return deriveSecretForTLSHash(s.hash, s.secret, serverHandshakeTrafficLabel, transcript)
}

type masterSecretTLS13 struct {
	secret []byte
	hash   tlsHash
}

func (s *handshakeSecretTLS13) masterSecret() *masterSecretTLS13 {
	derived := deriveSecretForTLSHash(s.hash, s.secret, "derived", nil)
	secret := extractForTLSHash(s.hash, nil, derived)
	clear(derived)
	return &masterSecretTLS13{secret: secret, hash: s.hash}
}

func (s *masterSecretTLS13) clientTrafficSecret(transcript hash.Hash) []byte {
	return deriveSecretForTLSHash(s.hash, s.secret, clientApplicationTrafficLabel, transcript)
}

func (s *masterSecretTLS13) serverTrafficSecret(transcript hash.Hash) []byte {
	return deriveSecretForTLSHash(s.hash, s.secret, serverApplicationTrafficLabel, transcript)
}

func (s *masterSecretTLS13) resumptionSecret(transcript hash.Hash) []byte {
	return deriveSecretForTLSHash(s.hash, s.secret, resumptionLabel, transcript)
}

func (s *masterSecretTLS13) exporter(transcript hash.Hash) func(string, []byte, int) ([]byte, error) {
	expMaster := deriveSecretForTLSHash(s.hash, s.secret, exporterLabel, transcript)
	return func(label string, context []byte, length int) ([]byte, error) {
		secret := deriveSecretForTLSHash(s.hash, expMaster, label, nil)
		if s.hash == hashGOST256 {
			digest := gostHashSumBytes(context)
			out := gostExpandLabel(secret, "exporter", digest[:], length)
			clear(secret)
			clear(digest[:])
			return out, nil
		}
		h := s.hash.New()
		_, _ = h.Write(context)
		digest := h.Sum(nil)
		out := expandLabelForTLSHash(s.hash, secret, "exporter", digest, length)
		clear(secret)
		clear(digest)
		return out, nil
	}
}
