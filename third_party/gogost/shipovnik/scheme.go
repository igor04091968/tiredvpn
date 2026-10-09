package shipovnik

import (
	"crypto"
	"errors"
	"fmt"
)

const (
	// CodeLength is the binary code length n.
	CodeLength = 2896
	// Dimension is the binary code dimension k.
	Dimension = 1448
	// SecretWeight is the required Hamming weight of every private key.
	SecretWeight = 318

	// PublicKeySize is the raw public-key size in bytes.
	PublicKeySize = 181
	// PrivateKeySize is the raw private-key size in bytes.
	PrivateKeySize = 362

	hashSize              = 64
	commitmentsPerRound   = 3
	commitmentRoundSize   = commitmentsPerRound * hashSize
	permutationPackedSize = 12 * CodeLength / 8
	longResponseSize      = permutationPackedSize + PrivateKeySize
	shortResponseSize     = 2 * PrivateKeySize
	matrixSize            = Dimension * PublicKeySize
	maxRounds             = 219
)

var (
	// ErrInvalidScheme reports use of the zero value or a forged Scheme value.
	ErrInvalidScheme = errors.New("shipovnik: invalid scheme")
	// ErrInvalidKey reports a malformed raw key or a nil key.
	ErrInvalidKey = errors.New("shipovnik: invalid key")
	// ErrInvalidSignature reports malformed signature encoding. A structurally
	// valid signature that fails its commitments returns (false, nil) instead.
	ErrInvalidSignature = errors.New("shipovnik: invalid signature encoding")
	// ErrInvalidOptions reports a negative worker count.
	ErrInvalidOptions = errors.New("shipovnik: invalid options")
	// ErrPrehashedMessage reports that crypto.Signer was asked to sign a digest.
	ErrPrehashedMessage = errors.New("shipovnik: prehashed messages are not supported")
	// ErrInvalidRandom reports a nil entropy source.
	ErrInvalidRandom = errors.New("shipovnik: nil entropy source")
)

const (
	referenceSchemeID uint8 = 1
	article70SchemeID uint8 = 2
)

// Scheme identifies one of the two immutable Shipovnik parameter profiles.
// Its fields are intentionally private. The zero value is invalid; obtain a
// value only from Reference or Article70.
type Scheme struct {
	id uint8
}

// Reference returns the current QAPP profile with delta=219.
func Reference() Scheme { return Scheme{id: referenceSchemeID} }

// Article70 returns the historical, research-only publication profile with
// delta=137. It must never be selected as an implicit downgrade.
func Article70() Scheme { return Scheme{id: article70SchemeID} }

// Options controls parallel round processing. Workers=0 selects an automatic
// value, Workers=1 forces serial processing, and Workers>1 requests that many
// workers (capped at the number of rounds).
type Options struct {
	Workers int
}

// HashFunc implements crypto.SignerOpts. Shipovnik signs the original message.
func (Options) HashFunc() crypto.Hash { return crypto.Hash(0) }

// Name returns the stable profile name or an empty string for an invalid Scheme.
func (s Scheme) Name() string {
	switch s.id {
	case referenceSchemeID:
		return "Shipovnik-Reference"
	case article70SchemeID:
		return "Shipovnik-Article70"
	default:
		return ""
	}
}

func (s Scheme) String() string {
	if name := s.Name(); name != "" {
		return name
	}
	return "Shipovnik-Invalid"
}

// Rounds returns delta, or zero for an invalid Scheme.
func (s Scheme) Rounds() int {
	switch s.id {
	case referenceSchemeID:
		return 219
	case article70SchemeID:
		return 137
	default:
		return 0
	}
}

// MinSignatureSize returns the shortest valid encoding for the profile.
func (s Scheme) MinSignatureSize() int {
	return s.Rounds() * (commitmentRoundSize + shortResponseSize)
}

// MaxSignatureSize returns the longest valid encoding for the profile.
func (s Scheme) MaxSignatureSize() int {
	return s.Rounds() * (commitmentRoundSize + longResponseSize)
}

func (s Scheme) validate() error {
	if s.Rounds() == 0 {
		return ErrInvalidScheme
	}
	return nil
}

func invalidKeyf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidKey, fmt.Sprintf(format, args...))
}

func invalidSignaturef(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidSignature, fmt.Sprintf(format, args...))
}
