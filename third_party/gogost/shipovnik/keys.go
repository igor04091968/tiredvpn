package shipovnik

import (
	"context"
	"crypto"
	"crypto/subtle"
	"io"
)

// PublicKey is an immutable Shipovnik public key bound to one Scheme.
type PublicKey struct {
	scheme Scheme
	data   [PublicKeySize]byte
}

// PrivateKey is an immutable Shipovnik private key bound to one Scheme.
type PrivateKey struct {
	scheme Scheme
	data   [PrivateKeySize]byte
	public [PublicKeySize]byte
}

// NewPublicKey validates and copies a raw public key for scheme.
func (s Scheme) NewPublicKey(raw []byte) (*PublicKey, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if len(raw) != PublicKeySize {
		return nil, invalidKeyf("public key has %d bytes, want %d", len(raw), PublicKeySize)
	}
	key := &PublicKey{scheme: s}
	copy(key.data[:], raw)
	return key, nil
}

// NewPrivateKey validates and copies a raw private key, then derives its public
// key using the canonical QAPP matrix.
func (s Scheme) NewPrivateKey(raw []byte) (*PrivateKey, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if len(raw) != PrivateKeySize {
		return nil, invalidKeyf("private key has %d bytes, want %d", len(raw), PrivateKeySize)
	}
	if weight := hammingWeight(raw); weight != SecretWeight {
		return nil, invalidKeyf("private key weight is %d, want %d", weight, SecretWeight)
	}
	key := &PrivateKey{scheme: s}
	copy(key.data[:], raw)
	syndrome(key.public[:], key.data[:])
	return key, nil
}

// NewPublicKey is the package-level form of Scheme.NewPublicKey.
func NewPublicKey(scheme Scheme, raw []byte) (*PublicKey, error) {
	return scheme.NewPublicKey(raw)
}

// NewPrivateKey is the package-level form of Scheme.NewPrivateKey.
func NewPrivateKey(scheme Scheme, raw []byte) (*PrivateKey, error) {
	return scheme.NewPrivateKey(raw)
}

// GenerateKey creates a uniformly sampled fixed-weight private key. Entropy is
// read sequentially even when later signing operations use multiple workers.
func (s Scheme) GenerateKey(random io.Reader) (*PrivateKey, error) {
	return s.GenerateKeyContext(context.Background(), random)
}

// GenerateKeyContext is GenerateKey with cancellation.
func (s Scheme) GenerateKeyContext(ctx context.Context, random io.Reader) (*PrivateKey, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	source, err := newEntropySource(ctx, random)
	if err != nil {
		return nil, err
	}
	defer source.close()
	key := &PrivateKey{scheme: s}
	if err := generateFixedWeightSecret(source, key.data[:]); err != nil {
		clear(key.data[:])
		return nil, err
	}
	syndrome(key.public[:], key.data[:])
	return key, nil
}

// Scheme returns the profile to which k is bound.
func (k *PublicKey) Scheme() Scheme {
	if k == nil {
		return Scheme{}
	}
	return k.scheme
}

// Scheme returns the profile to which k is bound.
func (k *PrivateKey) Scheme() Scheme {
	if k == nil {
		return Scheme{}
	}
	return k.scheme
}

// Bytes returns a copy of the raw public key. The profile is not encoded.
func (k *PublicKey) Bytes() []byte {
	if k == nil {
		return nil
	}
	out := make([]byte, PublicKeySize)
	copy(out, k.data[:])
	return out
}

// Bytes returns a copy of the raw private key. The profile is not encoded.
func (k *PrivateKey) Bytes() []byte {
	if k == nil {
		return nil
	}
	out := make([]byte, PrivateKeySize)
	copy(out, k.data[:])
	return out
}

// Equal reports whether both public-key bytes and schemes match.
func (k *PublicKey) Equal(other crypto.PublicKey) bool {
	if k == nil {
		return other == nil
	}
	var candidate *PublicKey
	switch value := other.(type) {
	case *PublicKey:
		candidate = value
	case PublicKey:
		candidate = &value
	default:
		return false
	}
	return candidate != nil && k.scheme == candidate.scheme &&
		subtle.ConstantTimeCompare(k.data[:], candidate.data[:]) == 1
}

// Equal reports whether both private-key bytes and schemes match.
func (k *PrivateKey) Equal(other crypto.PrivateKey) bool {
	if k == nil {
		return other == nil
	}
	var candidate *PrivateKey
	switch value := other.(type) {
	case *PrivateKey:
		candidate = value
	case PrivateKey:
		candidate = &value
	default:
		return false
	}
	return candidate != nil && k.scheme == candidate.scheme &&
		subtle.ConstantTimeCompare(k.data[:], candidate.data[:]) == 1
}

// Public returns a fresh copy of the corresponding public key.
func (k *PrivateKey) Public() crypto.PublicKey {
	if k == nil {
		return nil
	}
	public := &PublicKey{scheme: k.scheme, data: k.public}
	return public
}

// Sign implements crypto.Signer. digest must contain the original, unhashed
// message and opts.HashFunc() must be zero.
func (k *PrivateKey) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if value, ok := opts.(*Options); ok && value == nil {
		return k.SignMessage(random, digest, nil)
	}
	if opts != nil && opts.HashFunc() != crypto.Hash(0) {
		return nil, ErrPrehashedMessage
	}
	var options *Options
	switch value := opts.(type) {
	case Options:
		copy := value
		options = &copy
	case *Options:
		options = value
	}
	return k.SignMessage(random, digest, options)
}

var _ crypto.Signer = (*PrivateKey)(nil)
