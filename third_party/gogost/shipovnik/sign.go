package shipovnik

import (
	"context"
	"io"
	"runtime"
	"sync"
)

type roundScratch struct {
	permutation [CodeLength]uint16
	generation  uint16
	permuted    [PrivateKeySize]byte
	temporary   [PrivateKeySize]byte
	syndrome    [PublicKeySize]byte
}

func (s *roundScratch) clear() {
	clear(s.permutation[:])
	s.generation = 0
	clear(s.permuted[:])
	clear(s.temporary[:])
	clear(s.syndrome[:])
}

func (s *roundScratch) nextValidationGeneration() uint16 {
	s.generation++
	if s.generation == 0 {
		clear(s.permutation[:])
		s.generation = 1
	}
	return s.generation
}

type signingState struct {
	storage       []byte
	randomVectors []byte
	permutations  []byte
	commitments   []byte
	permutedU     []byte
	permutedXOR   []byte
}

func newSigningState(rounds int) *signingState {
	randomSize := rounds * PrivateKeySize
	permutationSize := rounds * permutationPackedSize
	commitmentSize := rounds * commitmentRoundSize
	permutedSize := rounds * PrivateKeySize
	storage := make([]byte, randomSize+permutationSize+commitmentSize+2*permutedSize)
	offset := 0
	state := &signingState{storage: storage}
	state.randomVectors = storage[offset : offset+randomSize]
	offset += randomSize
	state.permutations = storage[offset : offset+permutationSize]
	offset += permutationSize
	state.commitments = storage[offset : offset+commitmentSize]
	offset += commitmentSize
	state.permutedU = storage[offset : offset+permutedSize]
	offset += permutedSize
	state.permutedXOR = storage[offset : offset+permutedSize]
	return state
}

const signingStatePoolCapacity = 4

var (
	referenceSigningStates = make(chan *signingState, signingStatePoolCapacity)
	articleSigningStates   = make(chan *signingState, signingStatePoolCapacity)
)

func acquireSigningState(scheme Scheme) *signingState {
	pool := referenceSigningStates
	if scheme.id == article70SchemeID {
		pool = articleSigningStates
	}
	select {
	case state := <-pool:
		return state
	default:
		return newSigningState(scheme.Rounds())
	}
}

func releaseSigningState(scheme Scheme, state *signingState) {
	clear(state.storage)
	runtime.KeepAlive(state)
	pool := referenceSigningStates
	if scheme.id == article70SchemeID {
		pool = articleSigningStates
	}
	select {
	case pool <- state:
	default:
	}
}

const roundScratchPoolCapacity = 32

var roundScratches = make(chan *roundScratch, roundScratchPoolCapacity)

func acquireRoundScratches(count int) []*roundScratch {
	scratches := make([]*roundScratch, count)
	for i := range scratches {
		select {
		case scratches[i] = <-roundScratches:
		default:
			scratches[i] = new(roundScratch)
		}
	}
	return scratches
}

func releaseRoundScratches(scratches []*roundScratch) {
	for _, scratch := range scratches {
		scratch.clear()
		runtime.KeepAlive(scratch)
		select {
		case roundScratches <- scratch:
		default:
		}
	}
}

func populateSigningRound(
	ctx context.Context,
	source *entropySource,
	state *signingState,
	scratch *roundScratch,
	round int,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	u := state.randomVectors[round*PrivateKeySize : (round+1)*PrivateKeySize]
	if err := source.read(u); err != nil {
		return err
	}
	if err := generatePermutation(source, scratch.permutation[:]); err != nil {
		return err
	}
	packed := state.permutations[round*permutationPackedSize : (round+1)*permutationPackedSize]
	packPermutation(packed, scratch.permutation[:])
	return nil
}

func commitSigningRound(privateKey *PrivateKey, state *signingState, scratch *roundScratch, round int) {
	u := state.randomVectors[round*PrivateKeySize : (round+1)*PrivateKeySize]
	packed := state.permutations[round*permutationPackedSize : (round+1)*permutationPackedSize]
	commitment := state.commitments[round*commitmentRoundSize : (round+1)*commitmentRoundSize]
	permutedU := state.permutedU[round*PrivateKeySize : (round+1)*PrivateKeySize]
	permutedXOR := state.permutedXOR[round*PrivateKeySize : (round+1)*PrivateKeySize]

	syndrome(scratch.syndrome[:], u)
	c0 := hashPair(packed, scratch.syndrome[:])
	copy(commitment[:hashSize], c0[:])

	applyPermutation(permutedU, scratch.permutation[:], u)
	c1 := hashOne(permutedU)
	copy(commitment[hashSize:2*hashSize], c1[:])

	xorBytes(scratch.temporary[:], u, privateKey.data[:])
	applyPermutation(permutedXOR, scratch.permutation[:], scratch.temporary[:])
	c2 := hashOne(permutedXOR)
	copy(commitment[2*hashSize:], c2[:])
}

type signingRoundJob struct {
	round   int
	scratch *roundScratch
}

// buildSigningCommitments pipelines the sequential entropy producer with the
// independent commitment workers. A scratch carrying the unpacked permutation
// is handed directly to the consumer, avoiding a pack/unpack round trip.
func buildSigningCommitments(
	ctx context.Context,
	source *entropySource,
	privateKey *PrivateKey,
	state *signingState,
	workers int,
) error {
	rounds := privateKey.scheme.Rounds()
	scratches := acquireRoundScratches(workers)
	defer releaseRoundScratches(scratches)
	if workers <= 1 {
		for round := 0; round < rounds; round++ {
			if err := populateSigningRound(ctx, source, state, scratches[0], round); err != nil {
				return err
			}
			commitSigningRound(privateKey, state, scratches[0], round)
		}
		return ctx.Err()
	}

	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan signingRoundJob, workers)
	available := make(chan *roundScratch, workers)
	for _, scratch := range scratches {
		available <- scratch
	}
	consume := func() {
		for job := range jobs {
			if workCtx.Err() == nil {
				commitSigningRound(privateKey, state, job.scratch, job.round)
			}
			available <- job.scratch
		}
	}
	var wg sync.WaitGroup
	wg.Add(workers - 1)
	for range workers - 1 {
		go func() {
			defer wg.Done()
			consume()
		}()
	}

	var producerErr error
produce:
	for round := 0; round < rounds; round++ {
		var scratch *roundScratch
		select {
		case scratch = <-available:
		case <-workCtx.Done():
			producerErr = workCtx.Err()
			break produce
		}
		if err := populateSigningRound(workCtx, source, state, scratch, round); err != nil {
			available <- scratch
			producerErr = err
			cancel()
			break
		}
		select {
		case jobs <- signingRoundJob{round: round, scratch: scratch}:
		case <-workCtx.Done():
			available <- scratch
			producerErr = workCtx.Err()
			break produce
		}
	}
	close(jobs)
	consume()
	wg.Wait()
	if producerErr != nil {
		return producerErr
	}
	return ctx.Err()
}

// SignMessage signs an original (not prehashed) message.
func SignMessage(random io.Reader, privateKey *PrivateKey, message []byte, options *Options) ([]byte, error) {
	return SignMessageContext(context.Background(), random, privateKey, message, options)
}

// SignMessageTo appends a signature to dst and returns the extended slice.
func SignMessageTo(dst []byte, random io.Reader, privateKey *PrivateKey, message []byte, options *Options) ([]byte, error) {
	return SignMessageToContext(context.Background(), dst, random, privateKey, message, options)
}

// SignMessageContext is SignMessage with cancellation.
func SignMessageContext(ctx context.Context, random io.Reader, privateKey *PrivateKey, message []byte, options *Options) ([]byte, error) {
	return SignMessageToContext(ctx, nil, random, privateKey, message, options)
}

// SignMessageToContext appends a signature to dst and supports cancellation.
// On error it returns dst at its original length.
func SignMessageToContext(ctx context.Context, dst []byte, random io.Reader, privateKey *PrivateKey, message []byte, options *Options) ([]byte, error) {
	if privateKey == nil {
		return dst, invalidKeyf("nil private key")
	}
	if err := privateKey.scheme.validate(); err != nil {
		return dst, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	rounds := privateKey.scheme.Rounds()
	workers, automatic, err := resolveWorkers(options, rounds, automaticSignWorkers())
	if err != nil {
		return dst, err
	}
	source, err := newEntropySource(ctx, random)
	if err != nil {
		return dst, err
	}
	defer source.close()
	lease, err := acquireWorkerLease(ctx, workers, automatic)
	if err != nil {
		return dst, err
	}

	state := acquireSigningState(privateKey.scheme)
	defer releaseSigningState(privateKey.scheme, state)
	err = buildSigningCommitments(ctx, source, privateKey, state, lease.workers)
	lease.release()
	if err != nil {
		return dst, err
	}

	hash, err := hashMessageCommitments(ctx, message, state.commitments)
	if err != nil {
		return dst, err
	}
	var tritStorage [maxRounds]byte
	trits := challengeTritsTo(tritStorage[:], privateKey.scheme, hash)
	defer clear(trits)

	var offsetStorage [maxRounds + 1]int
	offsets := offsetStorage[:rounds+1]
	offsets[0] = len(state.commitments)
	for round, trit := range trits {
		responseSize := longResponseSize
		if trit == 2 {
			responseSize = shortResponseSize
		}
		offsets[round+1] = offsets[round] + responseSize
	}
	if err := ctx.Err(); err != nil {
		return dst, err
	}

	originalLength := len(dst)
	dst = append(dst, make([]byte, offsets[rounds])...)
	signature := dst[originalLength:]
	copy(signature, state.commitments)
	for round := 0; round < rounds; round++ {
		if round&15 == 0 {
			if err := ctx.Err(); err != nil {
				clear(signature)
				return dst[:originalLength], err
			}
		}
		response := signature[offsets[round]:offsets[round+1]]
		u := state.randomVectors[round*PrivateKeySize : (round+1)*PrivateKeySize]
		packed := state.permutations[round*permutationPackedSize : (round+1)*permutationPackedSize]
		switch trits[round] {
		case 0:
			copy(response, packed)
			copy(response[permutationPackedSize:], u)
		case 1:
			copy(response, packed)
			xorBytes(response[permutationPackedSize:], u, privateKey.data[:])
		case 2:
			permutedU := state.permutedU[round*PrivateKeySize : (round+1)*PrivateKeySize]
			permutedXOR := state.permutedXOR[round*PrivateKeySize : (round+1)*PrivateKeySize]
			copy(response[:PrivateKeySize], permutedU)
			xorBytes(response[PrivateKeySize:], permutedU, permutedXOR)
		}
	}
	return dst, nil
}

// SignMessage signs an original message with k.
func (k *PrivateKey) SignMessage(random io.Reader, message []byte, options *Options) ([]byte, error) {
	return SignMessage(random, k, message, options)
}

// SignMessageTo appends an original-message signature to dst.
func (k *PrivateKey) SignMessageTo(dst []byte, random io.Reader, message []byte, options *Options) ([]byte, error) {
	return SignMessageTo(dst, random, k, message, options)
}

// SignMessageContext signs an original message with cancellation.
func (k *PrivateKey) SignMessageContext(ctx context.Context, random io.Reader, message []byte, options *Options) ([]byte, error) {
	return SignMessageContext(ctx, random, k, message, options)
}

// SignMessageToContext appends a signature with cancellation.
func (k *PrivateKey) SignMessageToContext(ctx context.Context, dst []byte, random io.Reader, message []byte, options *Options) ([]byte, error) {
	return SignMessageToContext(ctx, dst, random, k, message, options)
}
