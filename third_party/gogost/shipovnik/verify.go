package shipovnik

import (
	"context"
	"crypto/subtle"
	"sync/atomic"
)

// Verify verifies a signature over the original message.
func Verify(publicKey *PublicKey, message, signature []byte, options *Options) (bool, error) {
	return VerifyContext(context.Background(), publicKey, message, signature, options)
}

// VerifyContext is Verify with cancellation.
func VerifyContext(ctx context.Context, publicKey *PublicKey, message, signature []byte, options *Options) (bool, error) {
	if publicKey == nil {
		return false, invalidKeyf("nil public key")
	}
	if err := publicKey.scheme.validate(); err != nil {
		return false, err
	}
	rounds := publicKey.scheme.Rounds()
	workers, automatic, err := resolveWorkers(options, rounds, automaticVerifyWorkers())
	if err != nil {
		return false, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if len(signature) < publicKey.scheme.MinSignatureSize() || len(signature) > publicKey.scheme.MaxSignatureSize() {
		return false, invalidSignaturef("length %d is outside [%d,%d]", len(signature), publicKey.scheme.MinSignatureSize(), publicKey.scheme.MaxSignatureSize())
	}
	commitmentSize := rounds * commitmentRoundSize
	if len(signature) < commitmentSize {
		return false, invalidSignaturef("missing commitments")
	}
	hash, err := hashMessageCommitments(ctx, message, signature[:commitmentSize])
	if err != nil {
		return false, err
	}
	var tritStorage [maxRounds]byte
	trits := challengeTritsTo(tritStorage[:], publicKey.scheme, hash)
	defer clear(trits)
	var offsetStorage [maxRounds + 1]int
	offsets := offsetStorage[:rounds+1]
	offsets[0] = commitmentSize
	for round, trit := range trits {
		responseSize := longResponseSize
		if trit == 2 {
			responseSize = shortResponseSize
		}
		offsets[round+1] = offsets[round] + responseSize
	}
	if offsets[rounds] != len(signature) {
		return false, invalidSignaturef("length %d does not match challenge-derived length %d", len(signature), offsets[rounds])
	}
	var roundOrderStorage [maxRounds]uint16
	roundOrder := roundOrderStorage[:rounds]
	next := 0
	for round, trit := range trits {
		if trit != 2 {
			roundOrder[next] = uint16(round)
			next++
		}
	}
	for round, trit := range trits {
		if trit == 2 {
			roundOrder[next] = uint16(round)
			next++
		}
	}
	lease, err := acquireWorkerLease(ctx, workers, automatic)
	if err != nil {
		return false, err
	}
	defer lease.release()
	scratches := acquireRoundScratches(lease.workers)
	defer releaseRoundScratches(scratches)
	var mismatch atomic.Uint32
	err = parallelTwoPhase(ctx, roundOrder, lease.workers, func(worker int, round int) error {
		trit := trits[round]
		response := signature[offsets[round]:offsets[round+1]]
		switch trit {
		case 0, 1:
			scratch := scratches[worker]
			generation := scratch.nextValidationGeneration()
			if err := validatePackedPermutationWithMarks(response[:permutationPackedSize], scratch.permutation[:], generation); err != nil {
				return err
			}
		case 2:
			if weight := hammingWeight(response[PrivateKeySize:]); weight != SecretWeight {
				return invalidSignaturef("revealed secret weight is %d, want %d", weight, SecretWeight)
			}
		default:
			return invalidSignaturef("invalid challenge trit %d", trit)
		}
		return nil
	}, func(worker, round int) error {
		scratch := scratches[worker]
		commitment := signature[round*commitmentRoundSize : (round+1)*commitmentRoundSize]
		response := signature[offsets[round]:offsets[round+1]]
		failed := 0
		switch trits[round] {
		case 0:
			packed := response[:permutationPackedSize]
			u := response[permutationPackedSize:]
			syndrome(scratch.syndrome[:], u)
			c0 := hashPair(packed, scratch.syndrome[:])
			failed |= 1 - subtle.ConstantTimeCompare(commitment[:hashSize], c0[:])
			applyPackedPermutation(scratch.permuted[:], packed, u)
			c1 := hashOne(scratch.permuted[:])
			failed |= 1 - subtle.ConstantTimeCompare(commitment[hashSize:2*hashSize], c1[:])
		case 1:
			packed := response[:permutationPackedSize]
			v := response[permutationPackedSize:]
			syndrome(scratch.syndrome[:], v)
			xorBytes(scratch.syndrome[:], scratch.syndrome[:], publicKey.data[:])
			c0 := hashPair(packed, scratch.syndrome[:])
			failed |= 1 - subtle.ConstantTimeCompare(commitment[:hashSize], c0[:])
			applyPackedPermutation(scratch.permuted[:], packed, v)
			c2 := hashOne(scratch.permuted[:])
			failed |= 1 - subtle.ConstantTimeCompare(commitment[2*hashSize:], c2[:])
		case 2:
			sigmaU := response[:PrivateKeySize]
			sigmaS := response[PrivateKeySize:]
			c1 := hashOne(sigmaU)
			failed |= 1 - subtle.ConstantTimeCompare(commitment[hashSize:2*hashSize], c1[:])
			xorBytes(scratch.temporary[:], sigmaU, sigmaS)
			c2 := hashOne(scratch.temporary[:])
			failed |= 1 - subtle.ConstantTimeCompare(commitment[2*hashSize:], c2[:])
		}
		if failed != 0 {
			mismatch.Store(1)
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return mismatch.Load() == 0, nil
}

// Verify verifies a signature with k.
func (k *PublicKey) Verify(message, signature []byte, options *Options) (bool, error) {
	return Verify(k, message, signature, options)
}

// VerifyContext verifies a signature with cancellation.
func (k *PublicKey) VerifyContext(ctx context.Context, message, signature []byte, options *Options) (bool, error) {
	return VerifyContext(ctx, k, message, signature, options)
}
